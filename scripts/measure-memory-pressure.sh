#!/usr/bin/env bash
#
# Campagne de mesure : comportement mémoire sous déverrouillages simultanés.
#
# OBJECTIF — caractériser, pas tester. On cherche à savoir si Argon2id, avec le
# profil **par défaut** (256 Mio, t=3, p=4), peut faire tomber une machine ou
# provoquer un échange massif lorsque plusieurs coffres sont ouverts en même temps.
# La conclusion détermine si une limitation de concurrence est nécessaire.
#
# CE QUE CETTE CAMPAGNE NE FAIT PAS — elle ne modifie aucun paramètre
# cryptographique. Le profil mesuré est celui qui est livré.
#
# Méthode : on lance N déverrouillages en parallèle, on échantillonne la somme des
# RSS de tous les processus concernés depuis /proc, et on retient le maximum
# observé. C'est la seule mesure qui rende compte du **pic agrégé** ; additionner
# les pics individuels surestimerait (les processus ne culminent pas forcément
# ensemble) et mesurer le RSS après coup ne verrait rien, la mémoire Argon2 étant
# libérée dès la dérivation terminée.
#
# Usage : scripts/measure-memory-pressure.sh [chemin-du-binaire]

set -uo pipefail

BIN="${1:-./target/release/passlock}"
PASSWORD='campagne de mesure memoire'
SAMPLES_PER_SECOND=200

if [[ ! -x "$BIN" ]]; then
    echo "binaire introuvable : $BIN" >&2
    echo "construisez-le avec : cargo build --release" >&2
    exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Un coffre **par niveau de concurrence**.
#
# C'est une correction de méthode importante. Une première version de cette
# campagne ouvrait N fois le MÊME coffre : le verrou exclusif en refusait N-1, et
# la mesure retournait un pic plat de 258 Mio quelle que soit la valeur de N.
# Elle mesurait la sérialisation par le verrou, pas la pression mémoire.
#
# Le cas réel à caractériser est celui de N coffres **distincts** ouverts
# simultanément — plusieurs profils, un coffre personnel et un coffre
# professionnel, ou simplement plusieurs instances lancées par l'utilisateur.
VAULTS=()
STATES=()
MAX_N=16
for ((i = 0; i < MAX_N; i++)); do
    vault="$WORK/coffre-$i.plk"
    state="$WORK/etat-$i"
    mkdir -p "$state"
    printf '%s\n%s\n' "$PASSWORD" "$PASSWORD" \
        | "$BIN" init --password-stdin --state-dir "$state" "$vault" >/dev/null
    VAULTS+=("$vault")
    STATES+=("$state")
done

# --- Contexte machine ------------------------------------------------------
TOTAL_KIB=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
AVAIL_KIB=$(awk '/MemAvailable/ {print $2}' /proc/meminfo)
CORES=$(nproc)

echo "== Contexte =="
printf '  mémoire totale      : %s Mio\n' "$((TOTAL_KIB / 1024))"
printf '  mémoire disponible  : %s Mio\n' "$((AVAIL_KIB / 1024))"
printf '  cœurs               : %s\n' "$CORES"
printf '  profil mesuré       : celui livré par défaut (256 Mio, t=3, p=4)\n'
echo

# --- Fonctions -------------------------------------------------------------

# Somme des RSS, en Kio, des processus encore vivants parmi ceux passés en argument.
sum_rss_kib() {
    local total=0
    local pid rss
    for pid in "$@"; do
        # Le processus peut disparaître entre la lecture et l'ouverture du fichier :
        # c'est un cas normal, pas une erreur.
        rss=$(awk '/^VmRSS/ {print $2}' "/proc/$pid/status" 2>/dev/null) || continue
        [[ -n "${rss:-}" ]] && total=$((total + rss))
    done
    printf '%s' "$total"
}

# Lance n déverrouillages simultanés et retourne (pic Kio, durée ms).
measure() {
    local n="$1"
    local pids=()
    local i

    local start
    start=$(date +%s%N)

    for ((i = 0; i < n; i++)); do
        # `$!` sur un pipeline donne le PID du **dernier** processus, donc de
        # passlock lui-même : c'est celui dont on veut le RSS.
        printf '%s\n' "$PASSWORD" \
            | "$BIN" verify --password-stdin \
                --state-dir "${STATES[$i]}" "${VAULTS[$i]}" >/dev/null 2>&1 &
        pids+=("$!")
    done

    local peak=0
    local alive=1
    while ((alive)); do
        local current
        current=$(sum_rss_kib "${pids[@]}")
        ((current > peak)) && peak=$current

        alive=0
        for i in "${pids[@]}"; do
            if kill -0 "$i" 2>/dev/null; then
                alive=1
                break
            fi
        done

        sleep "0.$(printf '%03d' $((1000 / SAMPLES_PER_SECOND)))"
    done

    # Un dernier échantillon après la fin : le pic peut survenir au moment de la
    # libération, avant que les processus ne disparaissent.
    local final
    final=$(sum_rss_kib "${pids[@]}")
    ((final > peak)) && peak=$final

    local end
    end=$(date +%s%N)
    printf '%s %s' "$peak" "$(((end - start) / 1000000))"
}

# --- Campagne --------------------------------------------------------------

echo "== Mesures =="
printf '  %6s  %14s  %12s  %10s  %s\n' "N" "PIC AGRÉGÉ" "PAR PROCESSUS" "DURÉE" "FRACTION DE LA RAM"

for n in 1 2 4 8 16; do
    read -r peak_ms duration_ms < <(measure "$n")

    # Un processus échoué n'aurait pas de RSS : on ignore les cas où rien n'a été
    # mesuré plutôt que d'afficher un zéro trompeur.
    if ((peak_ms == 0)); then
        printf '  %6s  %14s\n' "$n" "aucune mesure"
        continue
    fi

    per_process_ms=$((peak_ms / n))
    fraction_pct=$((peak_ms * 100 / TOTAL_KIB))

    printf '  %6s  %11s Mio  %9s Mio  %7s ms  %s%%\n' \
        "$n" \
        "$((peak_ms / 1024))" \
        "$((per_process_ms / 1024))" \
        "$duration_ms" \
        "$fraction_pct"
done

echo
echo "== Méthode =="
cat <<'NOTES'
  N coffres DISTINCTS sont ouverts simultanément, un processus par coffre. Ouvrir
  N fois le même coffre ne mesurerait rien : le verrou exclusif en refuserait N-1.

  Le pic agrégé est la somme des RSS échantillonnée à ~200 Hz pendant toute la
  durée de la campagne. Somme des pics individuels surestimerait (les dérivations
  ne culminent pas forcément ensemble) ; un RSS mesuré après coup ne verrait rien,
  la mémoire Argon2 étant libérée dès la dérivation terminée.

  Aucun paramètre cryptographique n'est modifié : le profil mesuré est celui qui
  est livré.

  Limite : un dépassement de la mémoire disponible ne provoque pas d'échec franc sur
  Linux. Le noyau échange, ce qui allonge brutalement la durée au lieu de refuser.
  Ce scénario n'a pas été provoqué — il faudrait saturer la machine, ce qui
  perturberait l'environnement de mesure.
NOTES
