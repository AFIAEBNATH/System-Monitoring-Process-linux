#!/bin/bash

#  Configuration ==========
CPU_THRESHOLD=80
MEM_THRESHOLD=80
DISK_THRESHOLD=80
INTERVAL=2
DURATION_MINUTES=30 
SAVE_DIR="$HOME/resource_monitor_logs" 

ALERT_SOUND="/usr/share/sounds/alsa/Front_Center.wav"
LOG_FILE="$SAVE_DIR/resource_log_$(date +%F_%H-%M-%S).csv"
INFECTED_LOG="$SAVE_DIR/infected_files_$(date +%F_%H-%M-%S).log"
VIRUS_SCAN_INTERVAL=600
LAST_VIRUS_SCAN=0
IDLE_WARNING_SHOWN=0
TOTAL_CPU=0
TOTAL_MEM=0
TOTAL_DISK=0
READINGS=0
BANDWIDTH_RX_PREV=0
BANDWIDTH_TX_PREV=0

EMAIL="c223236@ugrad.iiuc.ac.bd"

# Colors 
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

#  Dependency Check ==========
declare -A packages
packages=(
  [bc]="bc"
  [aplay]="alsa-utils"
  [notify-send]="libnotify-bin"
  [top]="procps"
  [free]="procps"
  [df]="coreutils"
  [gnuplot]="gnuplot"
  [upower]="upower"
  [hostname]="hostname"
  [ip]="iproute2"
  [sensors]="lm-sensors"
  [zenity]="zenity"
  [vnstat]="vnstat"
  [curl]="curl"
  [clamscan]="clamav"
  [inotifywait]="inotify-tools"
  [msmtp]="msmtp"
)

echo -e "${CYAN} Checking dependencies...${NC}"
for cmd in "${!packages[@]}"; do
  if ! command -v "$cmd" &>/dev/null; then
    pkg=${packages[$cmd]}
    echo -e "${RED}Missing: $cmd. Installing package: $pkg...${NC}"
    sudo apt install -y "$pkg" || echo -e "${RED}⚠ Failed to install: $pkg${NC}"
  else
    echo -e "${GREEN}✔ $cmd is already installed.${NC}"
  fi
done

#  Directory Setup ==========
mkdir -p "$SAVE_DIR"
touch "$LOG_FILE"
echo "Time,CPU (%),Memory (%),Disk (%),Temp (°C),Battery (%),Network,Bandwidth RX (KB/s),Bandwidth TX (KB/s),Public IP,Top CPU Process,Top MEM Process" >> "$LOG_FILE"

#  Prompt Thresholds ==========
read -p " CPU threshold (default $CPU_THRESHOLD): " custom_cpu
read -p " Memory threshold (default $MEM_THRESHOLD): " custom_mem
read -p " Disk threshold (default $DISK_THRESHOLD): " custom_disk
CPU_THRESHOLD=${custom_cpu:-$CPU_THRESHOLD}
MEM_THRESHOLD=${custom_mem:-$MEM_THRESHOLD}
DISK_THRESHOLD=${custom_disk:-$DISK_THRESHOLD}


# Alert Functions ==========

send_email_alert() {
  local subject="$1"
  local body="$2"
  local log_file="$SAVE_DIR/email_debug.log"

  echo -e "\n[ $(date '+%Y-%m-%d %H:%M:%S')] Trying to send email..." >> "$log_file"
  echo "To: $EMAIL" >> "$log_file"
  echo "Subject: $subject" >> "$log_file"
  echo "Body: $body" >> "$log_file"

  {
    echo "To: $EMAIL"
    echo "Subject: $subject"
    echo "Content-Type: text/plain; charset=UTF-8"
    echo
    echo "$body"
  } | msmtp "$EMAIL" >> "$log_file" 2>&1

  echo "[ Done]" >> "$log_file"
}

send_alert() {
  type=$1; value=$2
  notify-send "⚠ High $type Usage!" "$type usage is $value%"
  aplay "$ALERT_SOUND" &>/dev/null
  zenity --warning --title="Resource Alert" --text="$type usage is critically high: $value%" &>/dev/null &
  send_email_alert "Resource Alert: High $type Usage" "Warning: Your $type usage is critically high at $value%."
}

# The rest of the script remains the same...
#  Idle Notification ==========
send_idle_notice() {
  notify-send "🛌 System Idle" "All resource usage is low."
}

#  Network Checker ==========
check_network() {
  ping -c 1 8.8.8.8 &>/dev/null && echo "Online" || echo "Offline"
}

#  Battery Status ==========
get_battery() {
  upower -i /org/freedesktop/UPower/devices/battery_BAT0 2>/dev/null | awk '/percentage/ {print $2}' | tr -d '%'
}

#  Temperature Reader with Shared Folder Fallback ==========
get_temp() {
  local shared_temp_file="/media/sf_Shared/temp.txt"
  local temp

  # Try reading from host shared folder (VM environment)
  if [[ -f "$shared_temp_file" ]]; then
    temp=$(cat "$shared_temp_file" | tr -d '+°C \n\r')
  else
    # Try sensors command (physical machine)
    temp=$(sensors 2>/dev/null | grep -m 1 'Package id 0' | awk '{print $4}' | tr -d '+°C')
    if [[ -z "$temp" ]]; then
      # Fallback to thermal_zone files
      for zone in /sys/class/thermal/thermal_zone*/temp; do
        if [[ -f "$zone" ]]; then
          raw=$(cat "$zone")
          if [[ "$raw" =~ ^[0-9]+$ ]]; then
            temp=$(echo "scale=1; $raw / 1000" | bc)
            break
          fi
        fi
      done
    fi
  fi

  # If nothing found, show Unavailable
  if [[ -z "$temp" ]]; then
    temp="Unavailable"
  fi

  echo "$temp"
}

#  Bandwidth Monitor ==========
get_bandwidth() {
  local iface=$(ip route get 8.8.8.8 | awk '{print $5}')
  local rx=$(cat /sys/class/net/$iface/statistics/rx_bytes)
  local tx=$(cat /sys/class/net/$iface/statistics/tx_bytes)
  local rx_kbps=$(( (rx - BANDWIDTH_RX_PREV) / 1024 / INTERVAL ))
  local tx_kbps=$(( (tx - BANDWIDTH_TX_PREV) / 1024 / INTERVAL ))
  BANDWIDTH_RX_PREV=$rx
  BANDWIDTH_TX_PREV=$tx
  echo "$rx_kbps,$tx_kbps"
}

#  Public IP ==========
get_public_ip() {
  curl -s ifconfig.me || echo "Unavailable"
}

#  Top Processes ==========
get_top_processes() {
  top_cpu=$(ps -eo pid,comm,%cpu --sort=-%cpu | awk 'NR==2 {print $2 "(" $3 "%)"}')
  top_mem=$(ps -eo pid,comm,%mem --sort=-%mem | awk 'NR==2 {print $2 "(" $3 "%)"}')
  echo "$top_cpu,$top_mem"
}

#  Virus Scanner ==========
virus_scan() {
  echo -e "${YELLOW} Running virus scan...${NC}"
  clamscan -r --bell -i ~ > "$INFECTED_LOG"
  if grep -q "Infected files: 0" "$INFECTED_LOG"; then
    echo -e "${GREEN} No virus found.${NC}"
    zenity --info --title="Virus Scan" --text=" No virus found." &>/dev/null &
  else
    notify-send " Virus Detected!" "Check: $INFECTED_LOG"
    zenity --error --title="Virus Detected" --text=" Threat found!\nCheck log: $INFECTED_LOG" &>/dev/null &
    aplay "$ALERT_SOUND" &>/dev/null
    echo -e "${RED} Virus detected! See log: $INFECTED_LOG${NC}"
    local infected_count=$(grep "Infected files:" "$INFECTED_LOG" | awk '{print $3}')
    local infected_files=$(grep -v "^$" "$INFECTED_LOG" | grep -v "SCAN SUMMARY" | head -n 10)
    send_email_alert "Virus Alert: $infected_count infected files detected" "Virus scan detected $infected_count infected files.\n\nSample infected files:\n$infected_files\n\nCheck full log at: $INFECTED_LOG"
  fi
}

#  Fake Virus Watcher ==========
fake_virus_watcher() {
  local WATCH_DIR="$HOME/Downloads"
  echo -e "${YELLOW} Starting fake virus watcher on: $WATCH_DIR${NC}"
  inotifywait -m -e open --format '%w%f' "$WATCH_DIR" 2>/dev/null | while read -r FILE
  do
    basename_lower=$(basename "$FILE" | tr '[:upper:]' '[:lower:]')

    if [[ "$basename_lower" == virus* ]]; then
      notify-send " Virus Detected!" "Fake alert: $(basename "$FILE") is infected!"
      zenity --error --title="Virus Detected" --text="⚠ Fake Virus detected in file:\n$(basename "$FILE")" &>/dev/null &
      aplay "$ALERT_SOUND" &>/dev/null
      echo -e "${RED} Fake virus detected in: $FILE${NC}"
send_email_alert "Fake Virus Detected" "⚠ Fake virus alert!\n\nFile: $(basename "$FILE")\n\nLocation: $FILE"
    fi
  done
}

# Graph Export 
export_graph() {
  gnuplot <<-EOF
    set datafile separator ","
    set xdata time
    set timefmt "%Y-%m-%d %H:%M:%S"
    set format x "%H:%M"
    set terminal png size 1000,600
    set output "$SAVE_DIR/resource_graph.png"
    set title "CPU, Memory, Disk Usage Over Time"
    set xlabel "Time"
    set ylabel "Usage (%)"
    set key outside
    plot "$LOG_FILE" using 1:2 title "CPU (%)" with lines lw 2, \
         "$LOG_FILE" using 1:3 title "Memory (%)" with lines lw 2, \
         "$LOG_FILE" using 1:4 title "Disk (%)" with lines lw 2
EOF

  echo -e "${GREEN}Graph saved at: $SAVE_DIR/resource_graph.png${NC}"
}


#  Trap on Exit
trap '
  echo -e "\n Generating graph..."
  export_graph
  if [[ ! -z "$FAKE_VIRUS_PID" ]]; then
    kill "$FAKE_VIRUS_PID" 2>/dev/null
    echo "Stopped fake virus watcher (PID $FAKE_VIRUS_PID)"
  fi
  exit
' EXIT

#  Start Monitoring ==========
echo -e "${GREEN} Monitoring Started. Logs saved in $SAVE_DIR${NC}"

# Start fake virus watcher in background
fake_virus_watcher &
FAKE_VIRUS_PID=$!
echo "Fake virus watcher started with PID $FAKE_VIRUS_PID"

start_time=$(date +%s)

while true; do
  cpu=$(top -bn1 | grep "Cpu(s)" | awk '{print 100 - $8}')
  mem=$(free | awk '/Mem:/ {printf("%.1f", $3/$2 * 100)}')
  disk=$(df / | grep '/$' | awk '{print $5}' | tr -d '%')
  battery=$(get_battery)
  temp=$(get_temp)
  network=$(check_network)
  bandwidth=$(get_bandwidth)
  rx_kbps=$(echo $bandwidth | cut -d',' -f1)
  tx_kbps=$(echo $bandwidth | cut -d',' -f2)
  public_ip=$(get_public_ip)
  top_processes=$(get_top_processes)
  top_cpu=$(echo $top_processes | cut -d',' -f1)
  top_mem=$(echo $top_processes | cut -d',' -f2)
  now=$(date '+%Y-%m-%d %H:%M:%S')

  echo "$now,$cpu,$mem,$disk,$temp,$battery,$network,$rx_kbps,$tx_kbps,$public_ip,$top_cpu,$top_mem" >> "$LOG_FILE"

  TOTAL_CPU=$(echo "$TOTAL_CPU + $cpu" | bc)
  TOTAL_MEM=$(echo "$TOTAL_MEM + $mem" | bc)
  TOTAL_DISK=$(echo "$TOTAL_DISK + $disk" | bc)
  ((READINGS++))

  clear
  echo -e "${CYAN} $now${NC}"
  echo -e "  CPU:   ${YELLOW}$cpu%${NC} (Threshold: ${CPU_THRESHOLD}%)"
  echo -e "  Memory: ${YELLOW}$mem%${NC} (Threshold: ${MEM_THRESHOLD}%)"
  echo -e "  Disk:   ${YELLOW}$disk%${NC} (Threshold: ${DISK_THRESHOLD}%)"
  echo -e "  Battery: ${battery:-N/A}%"
  echo -e "  Temp: ${temp} °C"
  echo -e "  Network: $network"
  echo -e "  RX: ${rx_kbps:-0} KB/s | TX: ${tx_kbps:-0} KB/s"
  echo -e "  Public IP: $public_ip"
  echo -e "  Top CPU Process: $top_cpu"
  echo -e "  Top MEM Process: $top_mem"
  echo -e "  Log: $LOG_FILE"
  echo -e "${GREEN} Ctrl+C to stop monitoring${NC}"

  (( $(echo "$cpu > $CPU_THRESHOLD" | bc -l) )) && send_alert "CPU" "$cpu"
  (( $(echo "$mem > $MEM_THRESHOLD" | bc -l) )) && send_alert "Memory" "$mem"
  (( $(echo "$disk > $DISK_THRESHOLD" | bc -l) )) && send_alert "Disk" "$disk"

  if (( $(echo "$cpu < 10 && $mem < 20 && $disk < 50" | bc -l) )); then
    [ "$IDLE_WARNING_SHOWN" -eq 0 ] && send_idle_notice && IDLE_WARNING_SHOWN=1
  else
    IDLE_WARNING_SHOWN=0
  fi

  current_time=$(date +%s)
  if (( current_time - LAST_VIRUS_SCAN >= VIRUS_SCAN_INTERVAL )); then
    virus_scan
    LAST_VIRUS_SCAN=$current_time
  fi

  sleep "$INTERVAL"
  elapsed=$(( (current_time - start_time) / 60 ))
  [ "$elapsed" -ge "$DURATION_MINUTES" ] && echo -e "\n Auto-stopping after $DURATION_MINUTES minutes." && break
done
