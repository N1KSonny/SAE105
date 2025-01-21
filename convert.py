import pandas as pd
import os
import base64
from io import BytesIO
import matplotlib.pyplot as plt

# Fonction pour analyser le fichier CSV
def analyze_csv(csv_filename):
    try:
        # Lecture du fichier CSV
        data = pd.read_csv(csv_filename)
    except FileNotFoundError:
        print(f"Le fichier n'existe pas à l'emplacement {os.path.abspath(csv_filename)}")
        return None
    except pd.errors.EmptyDataError:
        print("Le fichier CSV est vide.")
        return None
    except Exception as e:
        print(f"Erreur lors de la lecture du fichier CSV : {e}")
        return None

    # Afficher les colonnes pour diagnostiquer l'erreur
    print("Colonnes du fichier CSV:", data.columns)

    # Nettoyer les espaces dans les noms de colonnes
    data.columns = data.columns.str.strip()

    # Vérifier la présence des colonnes nécessaires
    if 'IP Source' not in data.columns or 'IP Destination' not in data.columns:
        print("Les colonnes 'IP Source' ou 'IP Destination' n'existent pas dans le fichier CSV.")
        return None

    # Analyser les adresses IP envoyant le plus de paquets
    ip_counts = data['IP Source'].value_counts().head(10)

    # Nombre de paquets analysés et nombre d'IP sources et destinations
    total_packets = data.shape[0]
    unique_ips_sources = data['IP Source'].nunique()
    unique_ips_dest = data['IP Destination'].nunique()

    # Analyse des paquets par IP Destination
    ip_dest_counts = data['IP Destination'].value_counts().head(10)

    # Analyse des protocoles (si la colonne existe)
    if 'Protocol' in data.columns:
        protocol_counts = data['Protocol'].value_counts()
    else:
        protocol_counts = None

    # Analyse de la taille des paquets (si la colonne existe)
    if 'Longueur du Paquet' in data.columns:
        packet_size_counts = data['Longueur du Paquet'].describe()
    else:
        packet_size_counts = None

    # Générer un graphique des IPs sources envoyant le plus de paquets
    fig, ax = plt.subplots(figsize=(8, 4))  # Taille du graphique réduite pour plus de lisibilité
    ip_counts.plot(kind='bar', ax=ax, color='skyblue', edgecolor='black')
    ax.set_title('Top 10 des IPs sources envoyant le plus de paquets')
    ax.set_xlabel('Adresse IP source')
    ax.set_ylabel('Nombre de paquets')
    ax.set_xticklabels(ip_counts.index, rotation=45, ha='right', fontsize=8)

    # Convertir le graphique en image base64 pour l'intégrer dans le HTML
    img_buf = BytesIO()
    fig.savefig(img_buf, format='png', bbox_inches='tight')  # bbox_inches='tight' pour éviter que l'image soit coupée
    img_buf.seek(0)
    img_base64 = base64.b64encode(img_buf.read()).decode('utf8')
    plt.close(fig)

    # Générer un graphique des IPs Destination
    fig, ax = plt.subplots(figsize=(8, 4))  # Taille du graphique réduite pour plus de lisibilité
    ip_dest_counts.plot(kind='bar', ax=ax, color='lightcoral', edgecolor='black')
    ax.set_title('Top 10 des IPs Destination recevant le plus de paquets')
    ax.set_xlabel('Adresse IP Destination')
    ax.set_ylabel('Nombre de paquets')
    ax.set_xticklabels(ip_dest_counts.index, rotation=45, ha='right', fontsize=8)

    # Convertir le graphique en image base64 pour l'intégrer dans le HTML
    img_buf = BytesIO()
    fig.savefig(img_buf, format='png', bbox_inches='tight')
    img_buf.seek(0)
    img_base64_dest = base64.b64encode(img_buf.read()).decode('utf8')
    plt.close(fig)

    # Analyse des flags
    flag_counts = data['Flag'].value_counts()

    return total_packets, unique_ips_sources, unique_ips_dest, ip_counts, ip_dest_counts, flag_counts, protocol_counts, packet_size_counts, img_base64, img_base64_dest

# Génération du rapport HTML
def generate_html_report(total_packets, unique_ips_sources, unique_ips_dest, ip_counts, ip_dest_counts, flag_counts, protocol_counts, packet_size_counts, img_base64, img_base64_dest, html_filename):
    # Template HTML
    html_template = f"""
    <!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Rapport CSV</title>
        <style>
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background-color: #f0f0f5;
                margin: 0;
                padding: 0;
                color: #333;
            }}
            header {{
                background-color: #1f3b4c;
                color: white;
                padding: 20px;
                text-align: center;
                font-size: 2rem;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                border-bottom: 2px solid #1d2a34;
            }}
            main {{
                margin: 20px auto;
                max-width: 1100px;
                padding: 30px;
                background-color: white;
                border-radius: 8px;
                box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
            }}
            h2 {{
                color: #1f3b4c;
                margin-bottom: 20px;
                font-weight: bold;
            }}
            .info {{
                margin-bottom: 20px;
                padding: 15px;
                background-color: #f9f9f9;
                border-radius: 5px;
                box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            }}
            .data-table {{
                width: 100%;
                border-collapse: collapse;
                margin: 20px 0;
                box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
            }}
            .data-table th, .data-table td {{
                border: 1px solid #ddd;
                padding: 8px;
                text-align: center;
            }}
            .data-table th {{
                background-color: #1f3b4c;
                color: white;
            }}
            footer {{
                text-align: center;
                margin-top: 40px;
                padding: 15px;
                color: #888;
                font-size: 0.9rem;
            }}
        </style>
    </head>
    <body>
        <header>
            Rapport d'Analyse TCPDump
        </header>
        <main>
            <h2>Résumé des Données</h2>
            <div class="info">
                <strong>Nombre total de paquets analysés :</strong> {total_packets} <br>
                <strong>Nombre d'IP Source uniques :</strong> {unique_ips_sources} <br>
                <strong>Nombre d'IP Destination uniques :</strong> {unique_ips_dest} <br>
            </div>

            <h2>Graphique des IPs sources envoyant le plus de paquets</h2>
            <img src="data:image/png;base64,{img_base64}" alt="Graphique des IPs Source" />

            <h2>Graphique des IPs Destination recevant le plus de paquets</h2>
            <img src="data:image/png;base64,{img_base64_dest}" alt="Graphique des IPs Destination" />

            <h2>Répartition des Flags</h2>
            <div class="info">
                {flag_counts.to_frame().to_html()}
            </div>

            {f"<h2>Répartition des Protocoles</h2><div class='info'>{protocol_counts.to_frame().to_html()}</div>" if protocol_counts is not None else ""}
            
            {f"<h2>Statistiques sur les Tailles des Paquets</h2><div class='info'>{packet_size_counts.to_frame().to_html()}</div>" if packet_size_counts is not None else ""}
        </main>
        <footer>
            Rapport généré automatiquement à partir du fichier CSV.
        </footer>
    </body>
    </html>
    """

    # Sauvegarder le fichier HTML
    with open(html_filename, 'w', encoding='utf8') as html_file:
        html_file.write(html_template)

    print(f"Rapport HTML généré avec succès : {html_filename}")

# Exécution principale
def main():
    csv_filename = "C:/Users/33782/Documents/SAE105/Outputs/tcpdump_data.csv"
    html_filename = "C:/Users/33782/Documents/SAE105/Outputs/rapport_tcpdump.html"
    
    # Analyser le fichier CSV
    analysis_result = analyze_csv(csv_filename)
    
    if analysis_result:
        total_packets, unique_ips_sources, unique_ips_dest, ip_counts, ip_dest_counts, flag_counts, protocol_counts, packet_size_counts, img_base64, img_base64_dest = analysis_result
        # Générer le rapport HTML à partir des données extraites du CSV
        generate_html_report(total_packets, unique_ips_sources, unique_ips_dest, ip_counts, ip_dest_counts, flag_counts, protocol_counts, packet_size_counts, img_base64, img_base64_dest, html_filename)
    else:
        print("Aucune donnée n'a été extraite du fichier CSV.")

if __name__ == "__main__":
    main()
