import pandas as pd
import os
import base64
from io import BytesIO
import matplotlib.pyplot as plt

# Analyse du fichier CSV pour extraire et traiter les données nécessaires
def analyze_csv(csv_filename):
    try:
        # Lecture du fichier CSV
        data = pd.read_csv(csv_filename)
    except FileNotFoundError:
        print(f"Fichier introuvable : {os.path.abspath(csv_filename)}")
        return None
    except pd.errors.EmptyDataError:
        print("Le fichier CSV est vide.")
        return None
    except Exception as e:
        print(f"Erreur lors de la lecture : {e}")
        return None

    # Vérification et nettoyage des colonnes
    data.columns = data.columns.str.strip()  # Suppression des espaces dans les noms de colonnes
    if 'IP Source' not in data.columns or 'IP Destination' not in data.columns:
        print("Colonnes 'IP Source' ou 'IP Destination' manquantes.")
        return None

    # Analyses de base : IPs sources et destinations
    ip_counts = data['IP Source'].value_counts().head(10)  # Top 10 des IP sources
    ip_dest_counts = data['IP Destination'].value_counts().head(10)  # Top 10 des IP destinations

    # Statistiques générales
    total_packets = data.shape[0]
    unique_ips_sources = data['IP Source'].nunique()
    unique_ips_dest = data['IP Destination'].nunique()

    # Analyse des protocoles et tailles de paquets si les colonnes existent
    protocol_counts = data['Protocol'].value_counts() if 'Protocol' in data.columns else None
    packet_size_counts = data['Longueur du Paquet'].describe() if 'Longueur du Paquet' in data.columns else None

    # Création de graphiques pour visualisation
    img_base64 = create_bar_chart(ip_counts, "Top 10 des IPs sources", "IP Source", "Nombre de paquets")
    img_base64_dest = create_bar_chart(ip_dest_counts, "Top 10 des IPs destinations", "IP Destination", "Nombre de paquets")

    # Analyse des flags
    flag_counts = data['Flag'].value_counts()

    return total_packets, unique_ips_sources, unique_ips_dest, ip_counts, ip_dest_counts, flag_counts, protocol_counts, packet_size_counts, img_base64, img_base64_dest

# Génération de graphiques sous forme d'images base64
def create_bar_chart(data, title, xlabel, ylabel):
    fig, ax = plt.subplots(figsize=(8, 4))
    data.plot(kind='bar', ax=ax, color='skyblue', edgecolor='black')
    ax.set_title(title)
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.set_xticklabels(data.index, rotation=45, ha='right', fontsize=8)

    img_buf = BytesIO()
    fig.savefig(img_buf, format='png', bbox_inches='tight')
    img_buf.seek(0)
    img_base64 = base64.b64encode(img_buf.read()).decode('utf8')
    plt.close(fig)

    return img_base64

# Création d'un rapport HTML détaillé basé sur les analyses
def generate_html_report(total_packets, unique_ips_sources, unique_ips_dest, ip_counts, ip_dest_counts, flag_counts, protocol_counts, packet_size_counts, img_base64, img_base64_dest, html_filename):
    html_template = f"""
    <!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <title>Rapport CSV</title>
        <style>
            /* Style simplifié pour la présentation */
            body {{ font-family: Arial, sans-serif; background: #f9f9f9; margin: 0; padding: 0; }}
            header {{ background: #333; color: white; padding: 20px; text-align: center; }}
            main {{ padding: 20px; }}
            img {{ max-width: 100%; }}
        </style>
    </head>
    <body>
        <header>Rapport d'Analyse TCPDump</header>
        <main>
            <h2>Résumé des Données</h2>
            <p>Total de paquets : {total_packets}</p>
            <p>IPs Sources uniques : {unique_ips_sources}</p>
            <p>IPs Destinations uniques : {unique_ips_dest}</p>

            <h2>Graphiques</h2>
            <h3>Top IPs Sources</h3>
            <img src="data:image/png;base64,{img_base64}" />
            <h3>Top IPs Destinations</h3>
            <img src="data:image/png;base64,{img_base64_dest}" />

            <h2>Analyse des Flags</h2>
            <pre>{flag_counts.to_string()}</pre>

            {f"<h2>Analyse des Protocoles</h2><pre>{protocol_counts.to_string()}</pre>" if protocol_counts is not None else ""}
            {f"<h2>Statistiques sur la Taille des Paquets</h2><pre>{packet_size_counts.to_string()}</pre>" if packet_size_counts is not None else ""}
        </main>
    </body>
    </html>
    """
    with open(html_filename, 'w', encoding='utf8') as file:
        file.write(html_template)
    print(f"Rapport HTML généré : {html_filename}")

# Exécution principale
def main():
    csv_filename = "C:/Users/Sonny/Documents/SAE105/Outputs/tcpdump_data.csv"
    html_filename = "C:/Users/Sonny/Documents/SAE105/Outputs/rapport_tcpdump.html"

    analysis_result = analyze_csv(csv_filename)
    if analysis_result:
        generate_html_report(*analysis_result, html_filename)
    else:
        print("Analyse échouée.")

if __name__ == "__main__":
    main()
