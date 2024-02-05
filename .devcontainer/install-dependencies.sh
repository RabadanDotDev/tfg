apt-get update -y && apt-get upgrade -y
wget http://ftp.de.debian.org/debian/pool/contrib/m/msttcorefonts/ttf-mscorefonts-installer_3.7_all.deb -P /tmp
apt install -y /tmp/ttf-mscorefonts-installer_3.7_all.deb
fc-cache -f -v
tlmgr install fontspec
tlmgr install xcolor
