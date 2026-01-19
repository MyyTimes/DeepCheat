# DeepCheat 🎮

> Windows Memory Scanner & Pointer Chain Finder

## 🌐 Language | Dil
[English](#english) | [Türkçe](#turkce)

---

<a name="english"></a>
## 🇬🇧 English Version
> v2.0

A powerful memory scanning tool for Windows that finds pointer chains to dynamic memory addresses. Similar to Cheat Engine's pointer scanner but written in pure C.

### ✨ Features
- **Value Scanner** - Scan for int, float, double values in process memory
- **Pointer Chain Finder** - Find multi-level pointer chains
- **Module Filter** - Focus on specific modules (e.g., GameAssembly.dll)
- **Deep Search** - Recursive backward search from target address
- **Memory Region Viewer** - List and analyze memory regions

### 🛠️ Installation
```bash
git clone https://github.com/MyyTimes/DeepCheat.git
cd DeepCheat
gcc src/*.c -Iinclude -o DeepCheat.exe
./DeepCheat.exe
```

### 📖 Usage
1. Run DeepCheat as Administrator
2. Enter target process PID and module name
3. Select an option:
   - **Option 1**: Get module base address
   - **Option 3**: Scan for values
   - **Option 4**: Find pointer chains
   - **Option 5**: List memory regions

#### Pointer Chain Search
```
Enter the target address: 1945B358010
Enter max chain depth (1-10, recommended: 7): 7
Enter target module name (e.g. GameAssembly.dll): GameAssembly.dll
Enter chain file name: mypointers
```

### 📁 Project Structure
```
DeepCheat/
├── src/
│   ├── main.c           # Main program & menu
│   ├── MemoryRegion.c   # Memory region functions
│   ├── PointerChain.c   # Pointer chain scanner
│   └── DebugTerminal.c  # Debug output utilities
├── include/
│   ├── MemoryRegion.h
│   ├── PointerChain.h
│   └── DebugTerminal.h
├── Outputs/             # Pointer chain results
├── LICENSE
└── README.md
```

### ⚙️ Configuration
Edit `include/PointerChain.h` to adjust:
```c
#define MAX_DEPTH 10              // Max chain depth
#define MAX_OFFSET 0x8000         // Max offset between pointers
#define MAX_CHAINS_TO_SAVE 10000  // Max chains to save
```

---

<a name="turkce"></a>
## 🇹🇷 Türkçe Sürüm
> v2.0

Windows için güçlü bir bellek tarama aracı. Dinamik bellek adreslerine pointer zincirleri bulur. Cheat Engine'in pointer tarayıcısına benzer, saf C ile yazılmıştır.

### ✨ Özellikler
- **Değer Tarama** - Bellekte int, float, double değerler arar
- **Pointer Zincir Bulucu** - Çok seviyeli pointer zincirleri bulur
- **Modül Filtresi** - Belirli modüllere odaklanın (örn: GameAssembly.dll)
- **Derin Arama** - Hedef adresten geriye doğru recursive arar
- **Bellek Bölge Görüntüleyici** - Bellek bölgelerini listeler

### 🛠️ Kurulum
```bash
git clone https://github.com/MyyTimes/DeepCheat.git
cd DeepCheat
gcc src/*.c -Iinclude -o DeepCheat.exe
./DeepCheat.exe
```

### 📖 Kullanım
1. DeepCheat'i Yönetici olarak çalıştırın
2. Hedef işlem PID ve modül adını girin
3. Bir seçenek seçin:
   - **Seçenek 1**: Modül base adresi al
   - **Seçenek 3**: Değer tara
   - **Seçenek 4**: Pointer zinciri bul
   - **Seçenek 5**: Bellek bölgelerini listele

#### Pointer Zincir Arama
```
Enter the target address: 1945B358010
Enter max chain depth (1-10, recommended: 7): 7
Enter target module name (e.g. GameAssembly.dll): GameAssembly.dll
Enter chain file name: pointerlarim
```

### 📁 Dosya Yapısı
```
DeepCheat/
├── src/
│   ├── main.c           # Ana program & menü
│   ├── MemoryRegion.c   # Bellek bölge fonksiyonları
│   ├── PointerChain.c   # Pointer zincir tarayıcı
│   └── DebugTerminal.c  # Debug çıktı yardımcıları
├── include/
│   ├── MemoryRegion.h
│   ├── PointerChain.h
│   └── DebugTerminal.h
├── Outputs/             # Pointer zincir sonuçları
├── LICENSE
└── README.md
```

### ⚙️ Yapılandırma
`include/PointerChain.h` dosyasını düzenleyerek ayarlayın:
```c
#define MAX_DEPTH 10              // Maksimum zincir derinliği
#define MAX_OFFSET 0x8000         // Pointer'lar arası maksimum offset
#define MAX_CHAINS_TO_SAVE 10000  // Kaydedilecek maksimum zincir sayısı
```

---

## 📜 License
MIT License - See [LICENSE](LICENSE) for details.
