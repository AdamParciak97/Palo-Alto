import pandas as pd
import tkinter as tk
from tkinter import filedialog, messagebox, Toplevel, Text
import seaborn as sns
import matplotlib.pyplot as plt

def analyze_logs_with_bar_chart(logs_file, specific_ports):
    try:
        df = pd.read_csv(logs_file)
    except FileNotFoundError:
        messagebox.showerror("Błąd", f"Plik {logs_file} nie został znaleziony.")
        return

    if 'dport' not in df.columns:
        messagebox.showerror("Błąd", "Brak wymaganej kolumny 'dport' w pliku.")
        return

    if specific_ports:
        df = df[df['dport'].isin(specific_ports)]

    plt.figure(figsize=(10, 6))
    port_counts = df['dport'].value_counts()
    sns.barplot(x=port_counts.index, y=port_counts.values, palette="Blues_d")
    plt.xlabel("Port")
    plt.ylabel("Liczba wystąpień")
    plt.title("Wykres liczby wystąpień portów")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()

def display_top_10_threats_and_ports(logs_file):
    try:
        df = pd.read_csv(logs_file)
    except FileNotFoundError:
        messagebox.showerror("Błąd", f"Plik {logs_file} nie został znaleziony.")
        return

    if 'threatid' not in df.columns or 'dport' not in df.columns:
        messagebox.showerror("Błąd", "Brak wymaganych kolumn 'threatid' lub 'dport' w pliku.")
        return

    top_10_threats = df['threatid'].value_counts().head(10).index
    filtered_df = df[df['threatid'].isin(top_10_threats)]

    threat_ports = filtered_df.groupby('threatid')['dport'].unique().reset_index()
    threat_ports['dport'] = threat_ports['dport'].apply(lambda x: ', '.join(map(str, x)))

    # Wykres dla Top 10 zagrożeń
    threat_counts = filtered_df['threatid'].value_counts()
    plt.figure(figsize=(10, 6))
    sns.barplot(x=threat_counts.index, y=threat_counts.values, palette="viridis")
    plt.xlabel("Zagrożenie (threatid)")
    plt.ylabel("Liczba wystąpień")
    plt.title("Top 10 Zagrożeń")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()

    # Okno z tekstem dla Top 10 zagrożeń i portów
    top_window = Toplevel()
    top_window.title("Top 10 Zagrożeń i Porty")

    text = Text(top_window, wrap="none", width=80, height=15)
    text.pack(padx=10, pady=10)

    text.insert("1.0", "Zagrożenie\tPorty\n")
    text.insert("2.0", "-" * 60 + "\n")

    for _, row in threat_ports.iterrows():
        text.insert("end", f"{row['threatid']}\t{row['dport']}\n")

    text.config(state="disabled")

def analyze_threat_port_correlation(logs_file):
    try:
        df = pd.read_csv(logs_file)
    except FileNotFoundError:
        messagebox.showerror("Błąd", f"Plik {logs_file} nie został znaleziony.")
        return

    if 'threatid' not in df.columns or 'dport' not in df.columns:
        messagebox.showerror("Błąd", "Brak wymaganych kolumn 'threatid' lub 'dport' w pliku.")
        return

    threat_port_pivot = df.pivot_table(index='threatid', columns='dport', aggfunc='size', fill_value=0)

    plt.figure(figsize=(12, 8))
    sns.heatmap(threat_port_pivot, cmap="Blues", linewidths=0.5)
    plt.title("Korelacja między zagrożeniami a portami")
    plt.xlabel("Port docelowy")
    plt.ylabel("Zagrożenie (threatid)")
    plt.xticks(rotation=45)
    plt.yticks(rotation=0)
    plt.tight_layout()
    plt.show()

def display_top_5_source_addresses(logs_file):
    try:
        df = pd.read_csv(logs_file)
    except FileNotFoundError:
        messagebox.showerror("Błąd", f"Plik {logs_file} nie został znaleziony.")
        return

    if 'src' not in df.columns:
        messagebox.showerror("Błąd", "Brak wymaganej kolumny 'src' w pliku.")
        return

    top_5_sources = df['src'].value_counts().head(5)

    # Wykres dla Top 5 źródłowych adresów IP
    plt.figure(figsize=(10, 6))
    sns.barplot(x=top_5_sources.index, y=top_5_sources.values, palette="coolwarm")
    plt.xlabel("Adres IP Źródłowy")
    plt.ylabel("Liczba wystąpień")
    plt.title("Top 5 Adresów Źródłowych")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()

    # Okno z tekstem dla Top 5 adresów
    top_window = Toplevel()
    top_window.title("Top 5 Adresów Źródłowych")

    text = Text(top_window, wrap="none", width=60, height=10)
    text.pack(padx=10, pady=10)

    text.insert("1.0", "Adres IP\tLiczba wystąpień\n")
    text.insert("2.0", "-" * 40 + "\n")

    for ip, count in top_5_sources.items():
        text.insert("end", f"{ip}\t{count}\n")

    text.config(state="disabled")

def load_file():
    file_path = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
    if file_path:
        file_entry.delete(0, tk.END)
        file_entry.insert(0, file_path)

def analyze():
    logs_file = file_entry.get()
    if not logs_file:
        messagebox.showerror("Błąd", "Proszę wybrać plik CSV.")
        return

    try:
        specific_ports = list(map(int, ports_entry.get().split(',')))
    except ValueError:
        messagebox.showerror("Błąd", "Porty muszą być liczbami całkowitymi rozdzielonymi przecinkami.")
        return

    analyze_logs_with_bar_chart(logs_file, specific_ports)

def display_top_10():
    logs_file = file_entry.get()
    if not logs_file:
        messagebox.showerror("Błąd", "Proszę wybrać plik CSV.")
        return

    display_top_10_threats_and_ports(logs_file)

def display_correlation():
    logs_file = file_entry.get()
    if not logs_file:
        messagebox.showerror("Błąd", "Proszę wybrać plik CSV.")
        return

    analyze_threat_port_correlation(logs_file)

def display_top_5():
    logs_file = file_entry.get()
    if not logs_file:
        messagebox.showerror("Błąd", "Proszę wybrać plik CSV.")
        return

    display_top_5_source_addresses(logs_file)

root = tk.Tk()
root.title("Analiza portów i zagrożeń")

file_label = tk.Label(root, text="Wybierz plik CSV:")
file_label.pack(pady=5)
file_entry = tk.Entry(root, width=50)
file_entry.pack(pady=5)
file_button = tk.Button(root, text="Wybierz plik", command=load_file)
file_button.pack(pady=5)

ports_entry = tk.Entry(root, width=50)
ports_entry.pack(pady=5)

analyze_button = tk.Button(root, text="Analizuj porty", command=analyze)
analyze_button.pack(pady=10)

top_10_button = tk.Button(root, text="Top 10 Zagrożeń i Porty", command=display_top_10)
top_10_button.pack(pady=10)

top_5_button = tk.Button(root, text="Top 5 Adresów Źródłowych", command=display_top_5)
top_5_button.pack(pady=10)

root.mainloop()
