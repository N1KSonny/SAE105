import csv
import os
import pandas as pd

# Fonction pour extraire les données pertinentes
def extract_tcpdump_data(file_path):
    try:
        with open(file_path, encoding="utf8") as file:
            lines = file.readlines()
    except FileNotFoundError:
        print(f"Le fichier n'existe pas à l'emplacement {os.path.abspath(file_path)}")
        return None

    data = []
    
    for line in lines:
        if "Flags" in line:  # Vérifie la présence d'un flag dans la ligne
            parts = line.split()
            if len(parts) >= 9:  # Vérifie qu'il y a suffisamment d'informations
                timestamp = parts[0]
                src_ip = parts[2]
                dst_ip = parts[4]
                flag = parts[6]

                # Recherche de la longueur du paquet à partir de "length"
                length = "N/A"
                if "length" in line:  # Vérifie si "length" est présent dans la ligne
                    try:
                        length_index = parts.index("length") + 1
                        if length_index < len(parts):
                            length = parts[length_index]  # Récupère la valeur après "length"
                    except ValueError:
                        length = "N/A"  # Si "length" n'est pas dans parts, on garde "N/A"

                # Ajout des données dans la liste
                data.append([timestamp, src_ip, dst_ip, flag, length])
    
    return data

# Sauvegarde des données dans un fichier CSV
def save_to_csv(data, csv_filename):
    headers = ['Temps', 'IP Source', 'IP Destination', 'Flag', 'Longueur du Paquet']
    
    with open(csv_filename, mode='w', newline='', encoding='utf8') as file:
        writer = csv.writer(file)
        writer.writerow(headers)
        writer.writerows(data)

# Génération du fichier Markdown
def generate_markdown_report(data, md_filename):
    with open(md_filename, 'w', encoding='utf8') as file:
        file.write("# Rapport d'Événements TCPdump\n\n")
        file.write("## Tableau des Événements\n\n")
        file.write("| Temps | IP Source | IP Destination | Flag | Longueur du Paquet |\n")
        file.write("|-------|-----------|----------------|------|--------------------|\n")
        
        for row in data:
            file.write(f"| {row[0]} | {row[1]} | {row[2]} | {row[3]} | {row[4]} |\n")
    
    print(f"Rapport Markdown généré dans {md_filename}")

# Analyse des résultats
def analyze_data(csv_filename):
    # Chargement des données dans un DataFrame
    df = pd.read_csv(csv_filename)

    # Convertir la colonne 'Temps' en format datetime pour une analyse temporelle
    df['Temps'] = pd.to_datetime(df['Temps'], errors='coerce')

    # 1. Identifier les IP suspectes qui génèrent un grand nombre de paquets
    ip_counts = df['IP Source'].value_counts()
    suspicious_ips = ip_counts[ip_counts > 100]  # Seuil arbitraire : plus de 100 paquets

    # 2. Identifier les périodes avec un trafic anormal (ex: plus de 100 paquets par seconde)
    df['Secondes'] = df['Temps'].dt.floor('S')  # Arrondi à la seconde
    packets_per_second = df.groupby('Secondes').size()
    peak_traffic_times = packets_per_second[packets_per_second > 100]  # Seuil : plus de 100 paquets/s

    # 3. Analyse des types de flags
    flags_count = df['Flag'].value_counts()

    # Générer le rapport d'attaque
    print("\n## Rapport d'attaque détectée :")
    
    if not suspicious_ips.empty:
        print(f"IP suspectes ayant envoyé plus de 100 paquets :")
        print(suspicious_ips)
    else:
        print("Aucune IP suspecte détectée.")

    if not peak_traffic_times.empty:
        print("\nPériodes de pic de trafic détectées :")
        print(peak_traffic_times)
    else:
        print("Aucun pic de trafic détecté.")

    print("\nRépartition des types de flags :")
    print(flags_count)

# Main execution
def main():
    chemin_fichier_tcpdump = "C:/Users/33782/Documents/SAE105/Data/tcpdump.txt"
    csv_filename = "C:/Users/33782/Documents/SAE105/Outputs/tcpdump_data.csv"
    md_filename = "C:/Users/33782/Documents/SAE105/Outputs/rapport_tcpdump.md"
    
    # Extraction des données
    data = extract_tcpdump_data(chemin_fichier_tcpdump)
    
    if data:
        # Sauvegarde dans un fichier CSV
        save_to_csv(data, csv_filename)
        print(f"Fichier CSV généré : {csv_filename}")
        
        # Génération du fichier Markdown
        generate_markdown_report(data, md_filename)
        
        # Analyse des résultats
        analyze_data(csv_filename)
    else:
        print("Aucune donnée n'a été extraite.")

if __name__ == "__main__":
    main()
