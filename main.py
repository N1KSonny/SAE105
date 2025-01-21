import csv
import os
import pandas as pd

# Extraction des données pertinentes à partir du fichier texte tcpdump
def extract_tcpdump_data(file_path):
    try:
        with open(file_path, encoding="utf8") as file:
            lines = file.readlines()
    except FileNotFoundError:
        print(f"Le fichier n'existe pas à l'emplacement {os.path.abspath(file_path)}")
        return None

    data = []
    for line in lines:
        if "Flags" in line:  # Filtrer uniquement les lignes contenant des flags
            parts = line.split()
            if len(parts) >= 9:  # Vérifier si la ligne contient les informations nécessaires
                timestamp = parts[0]
                src_ip = parts[2]
                dst_ip = parts[4]
                flag = parts[6]
                
                # Récupérer la longueur du paquet si disponible
                length = "N/A"
                if "length" in line:
                    try:
                        length_index = parts.index("length") + 1
                        if length_index < len(parts):
                            length = parts[length_index]
                    except ValueError:
                        pass  # Si la longueur n'est pas trouvée, elle reste "N/A"

                data.append([timestamp, src_ip, dst_ip, flag, length])
    return data

# Enregistrer les données extraites dans un fichier CSV
def save_to_csv(data, csv_filename):
    headers = ['Temps', 'IP Source', 'IP Destination', 'Flag', 'Longueur du Paquet']
    with open(csv_filename, mode='w', newline='', encoding='utf8') as file:
        writer = csv.writer(file)
        writer.writerow(headers)
        writer.writerows(data)

# Générer un rapport Markdown à partir des données
def generate_markdown_report(data, md_filename):
    with open(md_filename, 'w', encoding='utf8') as file:
        file.write("# Rapport d'Événements TCPdump\n\n")
        file.write("## Tableau des Événements\n\n")
        file.write("| Temps | IP Source | IP Destination | Flag | Longueur du Paquet |\n")
        file.write("|-------|-----------|----------------|------|--------------------|\n")
        for row in data:
            file.write(f"| {row[0]} | {row[1]} | {row[2]} | {row[3]} | {row[4]} |\n")
    print(f"Rapport Markdown généré dans {md_filename}")

# Analyse des données enregistrées dans le fichier CSV
def analyze_data(csv_filename):
    df = pd.read_csv(csv_filename)
    df['Temps'] = pd.to_datetime(df['Temps'], errors='coerce')  # Convertir les dates

    # 1. Identifier les IP sources les plus actives
    ip_counts = df['IP Source'].value_counts()
    suspicious_ips = ip_counts[ip_counts > 100]  # IP ayant envoyé plus de 100 paquets

    # 2. Repérer les périodes de trafic élevé
    df['Secondes'] = df['Temps'].dt.floor('S')  # Grouper par seconde
    packets_per_second = df.groupby('Secondes').size()
    peak_traffic_times = packets_per_second[packets_per_second > 100]  # Plus de 100 paquets/s

    # 3. Répartition des flags
    flags_count = df['Flag'].value_counts()

    # Générer un rapport résumé
    print("\n## Rapport d'attaque détectée :")
    if not suspicious_ips.empty:
        print(f"IP suspectes ayant envoyé plus de 100 paquets :\n{suspicious_ips}")
    else:
        print("Aucune IP suspecte détectée.")

    if not peak_traffic_times.empty:
        print("\nPériodes de pic de trafic détectées :\n", peak_traffic_times)
    else:
        print("Aucun pic de trafic détecté.")

    print("\nRépartition des types de flags :\n", flags_count)

# Point d'entrée principal
def main():
    chemin_fichier_tcpdump = "C:/Users/Sonny/Documents/SAE105/Data/tcpdump.txt"
    csv_filename = "C:/Users/Sonny/Documents/SAE105/Outputs/tcpdump_data.csv"
    md_filename = "C:/Users/Sonny/Documents/SAE105/Outputs/rapport_tcpdump.md"
    
    # Extraire les données
    data = extract_tcpdump_data(chemin_fichier_tcpdump)
    
    if data:
        save_to_csv(data, csv_filename)  # Enregistrer dans un CSV
        print(f"Fichier CSV généré : {csv_filename}")
        
        generate_markdown_report(data, md_filename)  # Générer un rapport Markdown
        
        analyze_data(csv_filename)  # Analyser les résultats
    else:
        print("Aucune donnée n'a été extraite.")

if __name__ == "__main__":
    main()
