import subprocess

def install_misp():
    try:
        subprocess.run(["wget", "--no-cache", "-O", "/tmp/INSTALL.sh", "https://raw.githubusercontent.com/MISP/MISP/2.4/INSTALL/INSTALL.sh"], check=True)
        subprocess.run(["bash", "/tmp/INSTALL.sh"], check=True)
        print("MISP instalado correctamente.")
    except subprocess.CalledProcessError as e:
        print(f"Error durante la instalación de MISP: {e}")

install_misp()
