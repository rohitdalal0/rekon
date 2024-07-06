#!/bin/bash


# FIRST TIME TOOL SETUP
start_tool_setup='NO'


## LIST CONFIGURATION
target='/home/kali/Desktop/target.txt'
trust_resolv='/usr/share/seclists/Miscellaneous/dns-resolvers.txt'
untrust_resolv=''
dns_wordlist='/usr/share/wordlists/seclists/Discovery/DNS/dns-Jhaddix.txt'
tmp_dir="$HOME/Desktop/rekon/tmp"
home_dir="$HOME/Desktop/rekon"
user_list='' # UserName LIST
pass_list='' # PASSWORD LIST


## CONFIGURATION
remove_tmp_files='YES'
default_port_cred_enum='YES'
take_screenshot='YES'
subdomain_takeover_check='YES'

# Tool banner
banner(){
    echo """    
 ██▀███  ▓█████  ██ ▄█▀ ▒█████   ███▄    █ 
▓██ ▒ ██▒▓█   ▀  ██▄█▒ ▒██▒  ██▒ ██ ▀█   █ 
▓██ ░▄█ ▒▒███   ▓███▄░ ▒██░  ██▒▓██  ▀█ ██▒
▒██▀▀█▄  ▒▓█  ▄ ▓██ █▄ ▒██   ██░▓██▒  ▐▌██▒
░██▓ ▒██▒░▒████▒▒██▒ █▄░ ████▓▒░▒██░   ▓██░
░ ▒▓ ░▒▓░░░ ▒░ ░▒ ▒▒ ▓▒░ ▒░▒░▒░ ░ ▒░   ▒ ▒ 
  ░▒ ░ ▒░ ░ ░  ░░ ░▒ ▒░  ░ ▒ ▒░ ░ ░░   ░ ▒░.sh
  ░░   ░    ░   ░ ░░ ░ ░ ░ ░ ▒     ░   ░ ░ 
   ░        ░  ░░  ░       ░ ░           ░
CREATED BY: Rohit
FOLLOW ME: https://github.com/rohitdalal0
    """
}

## Tool Banner
banner

# TOOL SETUP CHECK
if [ "$start_tool_setup" = 'YES' ];then
    sudo apt update && sudo apt upgrade
    sudo apt autoremove
    sudo apt install golang
    ## ----------------- GO PATH SETUP --------------------
    echo '' >> $HOME/.zshrc
    echo 'export GOPATH=$HOME/go' >> $HOME/.zshrc
    echo 'export PATH=$PATH:$GOROOT/bin:$GOPATH/bin' >> /home/kali/.zshrc
    source $HOME/.zshrc

    ## ------------------ TOOLS SETUP ---------------------
    sudo go install github.com/hakluke/hakrawler@latest # Doesnot work
    sudo go install github.com/jaeles-project/gospider@latest
    sudo go install github.com/gwen001/github-subdomains@latest
    sudo go install github.com/tomnomnom/assetfinder@latest
    sudo go install github.com/d3mondev/puredns/v2@latest
    sudo go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    sudo go install -v github.com/LukaSikic/subzy@latest
    sudo go install github.com/d3mondev/puredns/v2@latest

    git clone https://github.com/m8sec/subscraper.git
    git clone https://github.com/nsonaniya2010/SubDomainizer.git
    wget https://github.com/RustScan/RustScan/releases/download/2.0.1/rustscan_2.0.1_amd64.deb
    git clone https://github.com/gwen001/github-search.git
    ## https://github.com/shmilylty/OneForAll.git

    mv subscraper $HOME/go/bin
    mv SubDomainizer $HOME/go/bin
    mv github-search $HOME/go/bin
    sudo dpkg -i rustscan_2.0.1_amd64.deb
    rm rustscan_2.0.1_amd64.deb
    
    sudo apt install altdns
    sudo apt install brutespray

    # Setting alias
fi

## Check if the file exists
if [ ! -e "$target" ]; then
    echo "File not found: $target"
    exit 1
fi

gospider_fun() {
    # Use a while loop to read each line
    while IFS= read -r line; do
        # Process each line as needed
        echo "[gospider]: Fetching domains ....."
        gospider -s "http://$line" -w | grep "^\[subdomains\]" | awk '{ print $3 }' >> $tmp_dir/gospider_domains.txt
    done < "$target"
}
sublister_fun() {
    # Use a while loop to read each line
    while IFS= read -r line; do
        # Process each line as needed
        echo "[Sublist3r]: Fetching domains ....."
        sublist3r -d "$line" | grep '^[a-zA-Z]' >> $tmp_dir/sublister_domains.txt
    done < "$target"
}
assetfinder_fun(){
    while IFS= read -r line; do
        # Process each line as needed
        echo "[assetfinder]: Fetching domains ....."
        assetfinder -subs-only $line >> $tmp_dir/assetfinder_domains.txt
    done < "$target"
    
}
hakrawler_fun(){
    while IFS= read -r line; do
        echo "$line" | httpx | hakrawler -subs -u | grep -E "$line" | awk -F // '{ print $2 }' | awk -F / '{ print $1 }' >> $tmp_dir/hakrawler_domains.txt
    done < "$target"
}
subdomainizer_fun(){
    GITHUB_TOKEN=$(awk '/github:/ {print $2}' /home/kali/.config/subfinder/provider-config.yaml | sed 's/\[//;s/\]//')
    python3 SubDomainizer.py -l "$target" -g -gt "$GITHUB_TOKEN" -san all -o $tmp_dir/subdomainizer_domains.txt
}
subscraper_fun(){
    while IFS= read -r line; do
        python3 subscraper.py target $line -M bufferoverrun,certsh,dnsbrute,dnsdumpster,archiveorg,search,threatcrowd >> $tmp_dir/subscraper_domains.txt
    done < "$target"
    #output to the tool folder as well
}
github_fun(){
    #touch "$tmp_dir/git-hub.txt"
    while IFS= read -r line; do
        github-subdomains -d $line -e -raw -t "$GITHUB_TOKEN"
        cat "$HOME/go/bin/$line.txt" >> "$tmp_dir/github_domains.txt"
        rm "$HOME/go/bin/$line.txt"
    done < "$target"
}
subfinder_fun(){
    subfinder -dL $target -all -o $tmp_dir/subfinder_domains.txt
}
puredns_fun(){
    puredns bruteforce $dns_wordlist --resolvers $trust_resolv -d $target --write $tmp_dir/puredns_domains.txt --write-wildcards $home_dir/wildcard-domains.txt
}
amass_fun(){
    amass enum -active -df $target -alts -brute -max-depth 5 -rf $trust_resolv -w $dns_wordlist -nocolor -o $tmp_dir/tmp_amass.txt
    cat "$tmp_dir/tmp_amass.txt" | awk '{ print $1 }' | grep -E -o '([a-zA-Z0-9-]+\.){1,5}[a-zA-Z]{2,}(\.[a-zA-Z]{2,})?' | sort | uniq >> $tmp_dir/amass_domains.txt
    rm "$tmp_dir/tmp_amass.txt"
}
oneforall_fun(){
    #Not working having bug
    return 0
}
github_py_fun(){
    while IFS= read -r line; do
        python3 github-subdomains.py -t "$GITHUB_TOKEN" -d $line >> $tmp_dir/github_py_domains.txt
    done < "$target"
}
altdns_fun(){
    altdns -i $target -w $dns_wordlist -t 150 -o $tmp_dir/altdns_domains.txt
}
httpx_fun(){
    httpx -l $target -mc 200 -t 150 -o $home_dir/live_domains.txt
    mv "$target" "$home_dir/target.txt"
}


main() {
    
    ## create tmp dir
    mkdir -p $tmp_dir

    ## Run recon tools
    gospider_fun
    sublister_fun
    assetfinder_fun
    hakrawler_fun
    subdomainizer_fun
    subscraper_fun
    github_fun

    subfinder_fun
    puredns_fun
    amass_fun
    ##oneforall_fun

    github_py_fun
    altdns_fun


    ## Sorting domains
    echo "Sorting domains .........."
    cat $tmp_dir/gospider_domains.txt $tmp_dir/sublister_domains.txt $tmp_dir/assetfinder_domains.txt $tmp_dir/hakrawler_domains.txt $tmp_dir/subdomainizer_domains.txt $tmp_dir/subscraper_domains.txt $tmp_dir/github_domains.txt $tmp_dir/subfinder_domains.txt $tmp_dir/puredns_domains.txt $tmp_dir/amass_domains.txtv $tmp_dir/github_py_domains.txt $tmp_dir/altdns_domains.txt | sort -u > $home_dir/sorted_domains.txt

    ## Filtering out live domains
    echo "Sorting live domains ......"
    httpx_fun

    ## remove tmp files
    if [ "$remove_tmp_files" = "YES" ];then
        rm -r $tmp_dir
    fi

    ## take screenshot
    if [ "$take_screenshot" = "YES" ];then
        eyewitness --web -f target --timeout 30 --threads 150 --no-prompt -d $home_dir/screenshots
    fi

    ## subdomain_takeover_check
    if [ "$subdomain_takeover_check" = "YES" ];then
        subzy run --targets $target --timeout 30 --concurrency 50 --vuln --output $home_dir/subdomain_takover_check.txt
    fi

    ## Port scans & default credential enumeration
    if [ "$default_port_cred_enum" = "YES" ];then
        mkdir $home_dir/port_scans
        mkdir $home_dir/services_enum
        while IFS= read -r line; do
            url=$(echo "$line" | awk -F // '{ print $2 }')
            rustscan -a "$url" --range 1-65535 -b 5000 --accessible -- -A -sVC -oG "$home_dir/port_scans/$url.gnmap"
            ## Brute force default credentials
            brutespray -f "$home_dir/port_scans/$url.gnmap" -t 100 -T 2 -U "$user_list" -P "$pass_list" -q -o $home_dir/services_enum
        done < "$target"
    fi
}



## start_script
main
