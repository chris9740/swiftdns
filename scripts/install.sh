#!/bin/bash

set -e

if [ "$EUID" -ne 0 ]; then
    echo "This script must be run as root."
    exit 1
fi

if [ ! -f Cargo.toml ]; then
    echo "This command needs to be executed in the source root directory."
    exit 1
fi

if ! command -v systemctl >/dev/null 2>&1; then
    echo "Systemd is required to install Swiftdns, but it does not appear to be installed on this system. Quitting."
    exit 1
fi

APP_NAME=swiftdns
APP_USER=$APP_NAME
APP_DIR="/etc/$APP_NAME"
FILTERS_DIR="$APP_DIR/filters"

C_LIGHT_CYAN='\033[0;36m'
C_LIGHT_GRAY='\033[0;37m'
C_RED='\033[1;31m'
C_WHITE_BOLD='\033[1;37m'
C_ITALIC='\033[3m'
C_OFF='\033[0m'

source ./assets/.metadata.sh

echo -e "${C_WHITE_BOLD}Starting installation for Swiftdns v${PKG_VERSION} (commit ${COMMIT_HASH})${C_OFF}"

print_info() {
    echo -e "\n${C_LIGHT_CYAN}($1)${C_OFF}"
}

create_resources() {
    adduser --quiet --system --shell /usr/sbin/nologin $APP_USER

    mkdir -p $APP_DIR
    mkdir -p $FILTERS_DIR

    if [ ! -f $FILTERS_DIR/whitelist.list ]; then
        cp ./assets/filters/whitelist.list $FILTERS_DIR/whitelist.list
    fi

    chown $APP_USER -R $APP_DIR
    chmod 755 -R $APP_DIR
}

create_config() {
    local config_file="$APP_DIR/config.toml"
    local checksum_file="$APP_DIR/.config.toml.md5" # checksum of the config file's original content

    write_config() {
        touch $checksum_file
        cp ./assets/config.toml $config_file
        md5sum $config_file | awk '{print $1}' | tee $checksum_file >/dev/null
    }

    if [ -f "$checksum_file" ]; then
        local local_checksum=$(md5sum $config_file | awk '{print $1}')
        local local_initial_checksum=$(cat $checksum_file)
        local remote_checksum=$(md5sum ./assets/config.toml | awk '{print $1}')

        # If the remote config hasn't changed since last install, we don't need to do anything
        if [ "$remote_checksum" = "$local_initial_checksum" ]; then
            return 0
        fi

        print_info "setting up config"

        # If the local config hasn't been edited since last install, we can overwrite it without asking
        if [ "$local_checksum" = "$local_initial_checksum" ]; then
            write_config
            echo "Successfully synced local config with remote."
            return 0
        else
            echo "Your config file has been edited since the last installation, so it cannot automatically be updated."

            show_diff() {
                echo
                echo -e "(${C_ITALIC}\$ diff $config_file ./assets/config.toml${C_OFF})"
                echo

                diff "$config_file" ./assets/config.toml --color || true # diff has non-zero exit code when file's aren't identical

                echo -e -n "\n${C_ITALIC}(press any key to continue)...${C_OFF}"
                read -n 1 -s
                echo
            }

            while true; do
                echo -e "\nHow would you like to proceed?"

                echo "  [K] = Keep my current config (default)"
                echo "  [D] = Show diff"
                echo "  [N] = Completely replace my local config with the new one"

                echo -e -n "\n> "

                read -p "" -r choice

                case "$choice" in
                    [Kk] | "")
                        echo "Okay, preserving your current config."
                        break
                        ;;
                    [Dd]) show_diff ;;
                    [Nn])
                        write_config
                        break
                        ;;
                    *) echo -e "\n(${C_RED}error:${C_OFF} invalid input)" ;;
                esac
            done
        fi
    else
        print_info "setting up config"
        write_config
        echo "Successfully created config file."
    fi
}

create_resources

create_config

while true; do
    declare -A recommended=(
        [Google]="google.list"
        [Facebook]="meta.list"
        [Microsoft]="microsoft.list"
        [Tiktok]="tiktok.list"
    )

    # If the user already has at least one of the recommended lists,
    # we don't want to bother them
    for filename in "${recommended[@]}"; do
        if [ -f "$FILTERS_DIR/$filename" ]; then
            break 2
        fi
    done

    print_info "configuring filters"

    echo -n "Swiftdns comes with a set of recommended privacy filters that blacklist "
    delim=""
    for item in "${!recommended[@]}"; do
        printf "%s" "$delim$item"
        delim=", "
    done
    echo -e "."

    read -p "Would you like to apply these? [y/N] " use_recommended

    case "$use_recommended" in
    [Yy])
        echo "Okay, copying lists... "

        for filename in "${recommended[@]}"; do
            cp -n ./assets/filters/$filename $FILTERS_DIR/$filename
        done

        echo "Done."
        break
        ;;
    [Nn] | "")
        echo "Got it, skipping."
        break
        ;;
    *)
        echo "Invalid answer, please try again."
        continue
        ;;
    esac

    break
done

cp -u ./assets/systemd/swiftdns.service /lib/systemd/system/swiftdns.service

print_info "reloading systemd"

systemctl daemon-reload
systemctl enable swiftdns.service
systemctl start swiftdns.service

service_state=$(systemctl show -p SubState --value swiftdns)

if [ "$service_state" != "running" ]; then
    echo
    echo -e "${C_RED}notice:${C_OFF} Systemctl failed to start the swiftdns service."
    echo -e "${C_RED}notice:${C_OFF} If you need help, or want to report a bug, please refer to $GITHUB_URL/issues."
    echo -e "${C_RED}notice:${C_OFF} Other than systemctl failing to start at the end, the install process is effectively finished."
    exit 1
fi

echo "Systemd successfully configured and reloaded."

echo
echo -e "Installation complete."
