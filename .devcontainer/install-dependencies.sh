# Update
apt-get update -y && apt-get upgrade -y

# Install fonts for latex
wget http://ftp.de.debian.org/debian/pool/contrib/m/msttcorefonts/ttf-mscorefonts-installer_3.7_all.deb -P /tmp
apt install -y /tmp/ttf-mscorefonts-installer_3.7_all.deb
fc-cache -f -v

# Setup python dev env
/usr/local/python/current/bin/python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
