# Opcode 提取工具

[English](README.md) | [繁體中文](README.zh-TW.md)

這個 Python 工具用於從二進位檔案中提取地址和 opcode 資訊，並將結果儲存為 CSV 檔案。以下是工具各部分的詳細說明：

## 安裝需求

在使用此工具之前，請確保已安裝以下 Python 套件：

- `r2pipe`：用於與 Radare2 互動以執行反組譯。
- `pandas`：用於處理和操作提取的資料。
- `tqdm`：用於顯示進度條以追蹤處理進度。

您可以使用以下指令安裝這些套件：

```bash
pip install -r requirements.txt
```
或
```bash
pip install r2pipe pandas tqdm
```

## 使用方法

要使用此工具，請按照以下步驟操作：

1. 將 Python 檔案 `get_opcode.py` 下載到您的本機。

2. 開啟終端或命令提示字元，並切換到工具所在的目錄。

3. 執行以下指令來使用工具：

   ```bash
   python get_opcode.py -d /path/to/binary/directory
   ```

   將 `/path/to/binary/directory` 替換為包含要處理的二進位檔案的目錄路徑。

### 命令列參數

- `-d, --directory`（必需）：包含要處理檔案的二進位檔案目錄路徑。
- `-o, --output`（可選）：輸出目錄路徑。如果未指定，預設為 `<binary_directory>_disassemble`。
- `-t, --timeout`（可選）：每個檔案分析的超時時間（秒），預設為 300 秒。

### 使用範例

```bash
# 基本使用，使用預設設定
python get_opcode.py -d /path/to/binary/directory

# 指定自訂輸出目錄
python get_opcode.py -d /path/to/binary/directory -o /path/to/output

# 設定自訂超時時間（600 秒）
python get_opcode.py -d /path/to/binary/directory -t 600

# 組合所有選項
python get_opcode.py -d /path/to/binary/directory -o /path/to/output -t 600
```

4. 工具將開始處理二進位檔案，並將提取的地址和 opcode 資訊儲存為 CSV 檔案。處理進度將顯示在終端中。

5. 處理完成後，提取的 CSV 檔案將儲存在輸出目錄中。輸出目錄將包含以下內容：
   - `results` 子目錄：包含每個二進位檔案的提取 CSV 檔案，保持與輸入目錄相同的相對路徑結構。
   - `extraction.log`：記錄提取過程以及任何錯誤或警告的日誌檔案。
   - `timing.log`：記錄每個檔案處理執行時間的日誌檔案。

## 功能特性

- **並行處理**：利用多核心 CPU 同時處理多個二進位檔案，加快提取速度。
- **資源管理**：實作 context manager 以確保 radare2 實例的正確清理，防止資源洩漏。
- **超時保護**：內建超時機制，防止在有問題的二進位檔案上掛起。
- **完整日誌記錄**：分別記錄提取過程和時間資訊的日誌，便於分析和除錯。
- **錯誤處理**：對各種邊界情況（包括打包、損壞或不完整的二進位檔案）進行強健的錯誤處理。
- **進度追蹤**：即時進度條以監控提取過程。
- **彈性輸出**：可自訂輸出目錄位置。

## 程式碼說明

以下是工具各部分的詳細說明：

### `configure_logging` 函數

此函數用於設定日誌記錄設定。它接受輸出目錄路徑作為參數，並返回兩個日誌記錄器物件：`extraction_logger` 和 `timing_logger`。

- `extraction_logger` 用於記錄提取過程中的錯誤。
- `timing_logger` 用於記錄每個檔案處理的執行時間。

日誌檔案將儲存在輸出目錄中。此函數還會清除現有的處理器，以防止重複的日誌記錄項目。

### `open_r2pipe` 函數

這是一個 context manager，確保 radare2 實例的正確資源管理。它會自動開啟和關閉 r2pipe 連接，即使在處理過程中發生異常也能保證清理。這可以防止資源洩漏，並確保在大批次處理期間系統的穩定性。

### `extract_features` 函數

此函數使用 radare2 從二進位檔案中提取 opcode 資訊。它會：
- 使用 `open_r2pipe` context manager 開啟二進位檔案，確保安全的資源處理
- 從二進位檔案中檢索所有節區（sections）
- 對於每個大小非零的節區，使用 `pDj` 指令反組譯指令
- 為每條指令提取地址、opcode 和節區名稱
- 返回包含提取資訊的字典列表

如果找不到節區（表示可能是打包、損壞或不完整的二進位檔案），將記錄錯誤並返回空列表。

### `extraction` 函數

此函數負責從指定的二進位檔案中提取地址和 opcode 資訊，並將結果儲存為 CSV 檔案。它接受以下參數：

- `input_file_path`：目標檔案的路徑。
- `output_csv_path`：輸出 CSV 檔案的路徑。
- `file_name`：目標檔案的名稱。
- `extraction_logger`：用於記錄提取過程的日誌記錄器物件。
- `timing_logger`：用於記錄執行時間的日誌記錄器物件。
- `timeout_seconds`：檔案分析允許的最長時間。
- `bash_script_path`：超時檢查腳本的路徑。

此函數執行以下步驟：
1. 檢查輸出檔案是否已存在（如果存在則跳過）
2. 執行超時檢查以避免在有問題的二進位檔案上掛起
3. 呼叫 `extract_features` 使用 radare2 提取 opcodes
4. 驗證 opcodes 是否成功提取
5. 使用 pandas 將結果儲存到 CSV 檔案
6. 記錄執行時間

如果在提取過程中發生任何錯誤，例如找不到檔案或沒有有效的反組譯結果，錯誤資訊將使用 `extraction_logger` 記錄。

### `get_args` 函數

此函數用於產生並行處理的參數列表。它接受以下參數：

- `binary_path`：包含二進位檔案的目錄路徑。
- `output_path`：儲存輸出 CSV 檔案的目錄路徑。
- `extraction_logger`：用於記錄提取過程的日誌記錄器物件。
- `timing_logger`：用於記錄執行時間的日誌記錄器物件。
- `timeout_seconds`：超時時間（秒）。
- `bash_script_path`：超時檢查腳本的路徑。

此函數會遍歷二進位目錄中的所有檔案，並為每個檔案產生一個元組，包含輸入檔案路徑、輸出檔案路徑、檔案名稱和日誌記錄器物件。這些元組將用作並行處理的參數。

### `parallel_process` 函數

此函數用於並行處理提取任務。它接受一個參數列表，其中每個參數都是一個元組，包含輸入檔案路徑、輸出檔案路徑、檔案名稱和日誌記錄器物件。

此函數使用 `ProcessPoolExecutor` 建立處理程序池，並將提取任務提交到池中進行並行處理。使用 `tqdm` 套件在終端中顯示進度。

### `setup_output_directory` 函數

此函數用於設定儲存提取檔案的輸出目錄。它接受輸入目錄路徑和可選的自訂輸出目錄路徑作為參數，並返回輸出目錄的路徑。

如果指定了自訂輸出目錄，將使用該目錄。否則，輸出目錄將命名為 `<binary_directory>_disassemble`，並位於與輸入目錄相同的層級，其中 `<binary_directory>` 是輸入目錄的名稱。此函數會建立輸出目錄（如果不存在），並在其中建立 `results` 子目錄。

### `parse_arguments` 函數

此函數用於解析命令列參數。它使用 `argparse` 模組來定義和解析參數。

工具接受以下參數：
- `-d` 或 `--directory`（必需）：指定包含二進位檔案的目錄路徑。
- `-o` 或 `--output`（可選）：指定自訂輸出目錄路徑。
- `-t` 或 `--timeout`（可選）：指定檔案分析的超時時間（秒），預設為 300。

### `main` 函數

此函數是工具的主要入口點，協調整個提取過程。它執行以下步驟：

1. 解析命令列參數以取得輸入目錄路徑。
2. 設定儲存提取檔案的輸出目錄。
3. 設定日誌記錄設定，包括提取日誌和時間日誌。
4. 產生並行處理的參數列表。
5. 執行並行處理以提取地址和 opcode 資訊，並將結果儲存為 CSV 檔案。

## 結論

這個 Python 工具提供了一種便捷的方式來從二進位檔案中提取地址和 opcode 資訊，並將結果儲存為 CSV 檔案。它利用 Radare2 進行反組譯，並使用並行處理來加快處理速度。

該工具需要安裝 `r2pipe`、`pandas` 和 `tqdm` 套件，並可以透過命令列介面使用。提取的 CSV 檔案將儲存在輸出目錄中，該目錄包含每個二進位檔案的提取 CSV 檔案（保持與輸入目錄相同的相對路徑結構），以及提取和時間日誌檔案。

透過使用此工具，您可以輕鬆分析二進位檔案，並獲得有價值的地址和 opcode 資訊，用於進一步的研究和分析。

## 參考資料

此工具使用了多個與 Python 3.11.4 相容的 Python 函式庫和工具。以下是每個工具的參考資料和其他資源：

1. **os 和 time**：用於作業系統互動和時間相關函數的內建 Python 函式庫。更多詳細資訊可以在 Python 3.11.4 的官方 Python 文件中找到：[Python 標準函式庫](https://docs.python.org/3.11/library/)。

2. **r2pipe**：用於使用 Radare2 編寫腳本的 Python 函式庫，Radare2 用於二進位分析。官方儲存庫和文件可在以下位置取得：[Radare2 GitHub](https://github.com/radareorg/radare2)。

3. **logging 和 argparse**：用於日誌記錄和解析命令列參數的標準 Python 函式庫。Python 3.11.4 的文件可在以下位置取得：[Logging](https://docs.python.org/3.11/library/logging.html) 和 [Argparse](https://docs.python.org/3.11/library/argparse.html)。

4. **pandas**：用於 Python 的強大資料操作和分析函式庫。官方文件和使用者指南：[Pandas 文件](https://pandas.pydata.org/pandas-docs/version/1.4.4/)。

5. **tqdm**：用於在 Python 迴圈中新增進度條的函式庫。儲存庫和文件：[tqdm GitHub](https://github.com/tqdm/tqdm)。

6. **multiprocessing 和 concurrent.futures**：用於並行執行和非同步程式設計的 Python 函式庫。Python 3.11.4 的特定文件可在以下位置取得：[Multiprocessing](https://docs.python.org/3.11/library/multiprocessing.html) 和 [Concurrent.futures](https://docs.python.org/3.11/library/concurrent.futures.html)。

這些參考資料為理解開發此 opcode 提取工具所使用的工具和函式庫提供了基礎。
