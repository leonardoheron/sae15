import os

def trad(tab):
    """
    tab - tableau contenant la ligne du fichier trié
    SORTIE : un tableau dont le drapeau à un nom cohérent
    """
    if tab[6] == '[S],':
        tab[6]  = "SYN"
    elif tab[6] == '[P],':
        tab[6] = "PUSH"
    elif tab[6] == '[R],':
        tab[6] = "RST"
    elif tab[6] == "[.],":
        tab[6] = "ACK"
    elif tab[6] == '[P.],':
        tab[6] = "PUSH ACK"
    elif tab[6] == '[S.],':
        tab[6] = "SYN ACK"
    elif tab[6] == '[F.],':
        tab[6] = "FIN ACK"
    return tab


def fnct(chemin: str):
    """
    chemin - str contenant le fichier à traiter
    SORTIE : un fichier csv contenant les informations trié
    """
    try:
        with open(chemin, encoding="utf8") as fh:
            files = fh.read()
    except:
        print("Le fichier n'existe pas %s", os.path.abspath(chemin))
        
    texte_decoup = files.split('\n')
        
    for event in texte_decoup:
        # Initialisation chaine de carcatere
        if event.startswith('11:42'):
            line = event.split()
            trad(line)
            if line[5] == "Flags":
                if "BP-Linux8" in line[2]:
                    line[2] = "BP-Linux8"
                if "BP-Linux8" in line[4]:
                    line[4] = "BP-Linux8"
                evenement='temps : '+line[0]+';'+' Adresse Ip source : '+line[2]+';'+' Adresse IP destinataire : '+line[4]+';'+' flag : '+line[6]+';'
                if line[6] == "SYN":
                    evenement += 'Numéro de séquence : '+line[8]+';'+' Taille de la fenêtre : '+line[10]+';'+' Longueur du paquet : '+line[len(line)-2]+';'+'Protocole :' +line[len(line)-1]+';'
                if line[6] == "PUSH":
                    evenement += 'Numéro de séquence : '+line[8]+';'+' Numéro accusé de réception : '+line[10]+';'
                    
                if line[6] == "ACK":
                    if line[len(line)-1] == "length 0":
                        evenement += 'Numéro accusé de réception : '+line[8]+';'+' Taille de la fenêtre : '+line[10]+';'+'Longueur du paquet : '+line[len(line)-1]+';'
                    if line[len(line)-1] != "length 0":
                        evenement += 'Numero de séquence :'+line[8]+';'+'Numéro accusé de réception : '+line[10]+';'+'Longueur du paquet : '+line[len(line)-1]+';'
                        
                if line[6] == "SYN ACK":
                    evenement += 'Numéro de séquence : '+line[8]+';'+' Numéro accusé de réception : '+line[10]+';'+'Longueur du paquet : '+line[len(line)-1]+';'
                if line[6] == "PUSH ACK":
                    evenement += 'Numéro de séquence : '+line[8]+';'+' Numéro accusé de réception : '+line[10]+';'+'Longueur du paquet : '+line[len(line)-1]+';'
                if line[6] == "FIN ACK":
                    evenement += 'Numero de séquence :'+line[8]+';'+'Numéro accusé de réception : '+line[10]+';'+'Longueur du paquet : '+line[len(line)-1]+';'
            if line[5] == 'ICMP':
                evenement='temps : '+line[0]+';'+' Adresse Ip source : '+line[2]+';'+' Adresse IP destinataire : '+line[4]+';'+' Protocole : '+line[5]+';'+'Status :'+line[6]+';'+'State :'+line[7]+';'+'Id :'+line[9]+';'
            
            with open('fichier.csv','a') as f:
                f.write(f"{evenement}\n")
    f.close()
    fh.close()
    print('Fichier CSV créé avec succès')
    
if __name__=="__main__":
    val = input("Entrer le chemin d'accès de votre fichier que vous souhaitez traiter : ")
    fnct(val)