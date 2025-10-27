# Opcode 提取工具

[English](README.md) | [繁體中文](README.zh-TW.md)

這個 Python 工具用於使用 Ghidra 從二進位檔案中提取地址和 opcode 資訊，並將結果儲存為 CSV 檔案。以下是工具各部分的詳細說明：

## 安裝需求

在使用此工具之前，請確保已安裝以下軟體：

- **Ghidra**：由美國國家安全局 (NSA) 開發的軟體逆向工程框架。可從 [Ghidra 官方網站](https://ghidra-sre.org/)下載。
- **Python 3.x** 以及以下套件：
  - `pandas`：用於處理和操作提取的資料。
  - `tqdm`：用於顯示進度條以追蹤處理進度。

您可以使用以下指令安裝所需的 Python 套件:

```bash
pip install pandas tqdm
```

## 使用方法

要使用此工具，請按照以下步驟操作：

1. 將 Python 檔案 `get_opcode.py` 和 `ghidra_opcode_script.py` 下載到您的本機。

2. 確保已安裝 Ghidra，並記下 `analyzeHeadless` 腳本的路徑（通常位於 `<ghidra_install_dir>/support/analyzeHeadless`）。

3. 開啟終端或命令提示字元，並切換到工具所在的目錄。

4. 執行以下指令來使用工具：

   ```bash
   python get_opcode.py -d /path/to/binary/directory -g /path/to/ghidra/analyzeHeadless
   ```

   將 `/path/to/binary/directory` 替換為包含要處理的二進位檔案的目錄路徑，並將 `/path/to/ghidra/analyzeHeadless` 替換為 Ghidra headless analyzer 的路徑。

### 命令列參數

- `-d, --directory`（必需）：包含要處理檔案的二進位檔案目錄路徑。
- `-g, --ghidra`（必需）：Ghidra headless analyzer (analyzeHeadless) 的路徑。
- `-o, --output`（可選）：輸出目錄路徑。如果未指定，預設為 `<binary_directory>_disassemble`。
- `-t, --timeout`（可選）：每個檔案分析的超時時間（秒），預設為 600 秒。

### 使用範例

```bash
# 基本使用，使用預設設定
python get_opcode.py -d /path/to/binary/directory -g ~/ghidra/support/analyzeHeadless

# 指定自訂輸出目錄
python get_opcode.py -d /path/to/binary/directory -g ~/ghidra/support/analyzeHeadless -o /path/to/output

# 設定自訂超時時間（1200 秒）
python get_opcode.py -d /path/to/binary/directory -g ~/ghidra/support/analyzeHeadless -t 1200

# 組合所有選項
python get_opcode.py -d /path/to/binary/directory -g ~/ghidra/support/analyzeHeadless -o /path/to/output -t 1200
```

4. 工具將開始處理二進位檔案，並將提取的地址和 opcode 資訊儲存為 CSV 檔案。處理進度將顯示在終端中。

5. 處理完成後，提取的 CSV 檔案將儲存在輸出目錄中。輸出目錄將包含以下內容：
   - `results` 子目錄：包含每個二進位檔案的提取 CSV 檔案，根據檔案名稱的前兩個字元組織到子目錄中。
   - `extraction.log`：記錄提取過程以及任何錯誤或警告的日誌檔案。
   - `timing.log`：記錄每個檔案處理執行時間的日誌檔案。

## 功能特性

- **並行處理**：利用多核心 CPU（2 倍 CPU 數量）同時處理多個二進位檔案，加快提取速度。
- **Ghidra 整合**：利用 Ghidra 強大的反組譯功能搭配 headless 模式進行自動化處理。
- **不執行自動分析**：使用 `-noanalysis` 旗標跳過 Ghidra 的自動分析階段，專注於反組譯以加快處理速度。
- **手動反組譯**：使用 `DisassembleCommand` 實作手動反組譯，以精確控制提取過程。
- **超時保護**：使用 Linux `timeout` 指令內建超時機制，防止在有問題的二進位檔案上掛起。
- **完整日誌記錄**：分別記錄提取過程和時間資訊的日誌，便於分析和除錯。
- **錯誤處理**：對各種邊界情況（包括打包、損壞或不完整的二進位檔案）進行強健的錯誤處理。
- **進度追蹤**：即時進度條以監控提取過程。
- **彈性輸出**：可自訂輸出目錄位置。
- **資源清理**：處理每個檔案後自動清理臨時 Ghidra 專案檔案。

## 程式碼說明

以下是工具各部分的詳細說明：

### `configure_logging` 函數

此函數用於設定日誌記錄設定。它接受輸出目錄路徑作為參數，並返回 `extraction_logger` 物件。

- `extraction_logger` 用於記錄提取過程中的錯誤。

日誌檔案將儲存在輸出目錄中。此函數還會清除現有的處理器，以防止重複的日誌記錄項目。請注意，時間資訊由 `ghidra_opcode_script.py` 在 Ghidra 分析階段直接記錄。

### `extract_features` 函數

此函數使用 Ghidra headless analyzer 從二進位檔案中提取 opcode 資訊。它會：
- 為當前檔案建立臨時專案資料夾
- 使用 `-noanalysis` 旗標執行 Ghidra headless analyzer 以加快處理速度
- 執行 `ghidra_opcode_script.py` 後處理腳本以提取 opcode
- 驗證 CSV 輸出檔案是否成功產生
- 處理完成後清理臨時專案資料夾

此函數使用 Linux `timeout` 指令防止在有問題的二進位檔案上掛起，並可設定超時時間。

### `extraction` 函數

此函數負責從指定的二進位檔案中提取地址和 opcode 資訊，並將結果儲存為 CSV 檔案。它接受以下參數：

- `input_file_path`：目標檔案的路徑。
- `output_csv_path`：輸出 CSV 檔案的路徑。
- `file_name`：目標檔案的名稱。
- `extraction_logger`：用於記錄提取過程的日誌記錄器物件。
- `output_dir`：輸出目錄路徑。
- `ghidra_headless_path`：Ghidra headless analyzer 的路徑。
- `timeout_seconds`：檔案分析允許的最長時間。

此函數執行以下步驟：
1. 檢查輸出檔案是否已存在（如果存在則跳過）
2. 呼叫 `extract_features` 執行 Ghidra 並提取 opcode
3. 驗證提取是否成功
4. 返回執行時間

如果提取過程中發生任何錯誤，錯誤資訊將使用 `extraction_logger` 記錄。錯誤只會記錄一次以避免重複訊息（例如，超時錯誤不會再記錄「無有效反組譯」訊息）。

### `ghidra_opcode_script.py`

這個 Ghidra Python 腳本在 Ghidra 的 headless 環境中執行，並執行實際的 opcode 提取：

1. **記憶體區塊分析**：遍歷程式中的所有記憶體區塊
2. **手動反組譯**：使用 `DisassembleCommand` 反組譯每個記憶體區塊（因為使用了 `-noanalysis` 旗標而必需）
3. **Opcode 提取**：提取每條指令的地址（整數型態）、opcode 和區段名稱
4. **資料收集**：在建立 CSV 檔案之前收集所有 opcode 以確保資料有效性
5. **CSV 產生**：僅在成功提取有效 opcode 時才建立 CSV 檔案
6. **計時**：記錄執行時間以進行效能分析

此腳本處理錯誤，例如缺少記憶體區塊（可能表示打包、損壞或不完整的二進位檔案）。

### `get_args` 函數

此函數用於產生並行處理的參數列表。它接受以下參數：

- `binary_path`：包含二進位檔案的目錄路徑。
- `output_path`：儲存輸出 CSV 檔案的目錄路徑。
- `extraction_logger`：用於記錄提取過程的日誌記錄器物件。
- `ghidra_headless_path`：Ghidra headless analyzer 的路徑。
- `timeout_seconds`：超時時間（秒）。

此函數遍歷二進位檔案目錄中的所有檔案（沒有副檔名的檔案），並為每個檔案產生一個元組，包含輸入檔案路徑、輸出檔案路徑、檔案名稱和其他處理參數。這些元組將用作並行處理的參數。

### `parallel_process` 函數

此函數用於並行處理提取任務。它接受一個參數列表，其中每個參數都是一個包含檔案資訊和處理參數的元組。

此函數使用 `ProcessPoolExecutor`，最多使用 2 倍 CPU 數量的 worker 來建立程序池，並將提取任務提交到池中進行並行處理。使用較高的 worker 數量（2 倍）是因為 Ghidra 大部分時間都在等待 I/O 操作。處理進度使用 `tqdm` 套件顯示在終端中。

### `setup_output_directory` 函數

此函數用於設定用於儲存提取檔案的輸出目錄。它接受輸入目錄路徑和可選的自訂輸出目錄路徑作為參數，並返回輸出目錄的路徑。

如果指定了自訂輸出目錄，將使用該目錄。否則，輸出目錄將命名為 `<binary_directory>_disassemble`，並位於與輸入目錄相同的層級。如果輸出目錄不存在，此函數會建立它，並在其中建立 `results` 和 `ghidra_projects` 子目錄。`ghidra_projects` 目錄用於臨時 Ghidra 專案檔案，並會自動清理。

### `parse_arguments` 函數

此函數用於解析命令列參數。它使用 `argparse` 模組來定義和解析參數。

此工具接受以下參數：
- `-d` 或 `--directory`（必需）：指定包含二進位檔案的目錄路徑。
- `-g` 或 `--ghidra`（必需）：指定 Ghidra headless analyzer 的路徑。
- `-o` 或 `--output`（可選）：指定自訂輸出目錄路徑。
- `-t` 或 `--timeout`（可選）：指定檔案分析的超時時間（秒），預設為 600。

### `main` 函數

此函數是工具的主要進入點，協調整個提取過程。它執行以下步驟：

1. 解析命令列參數以取得輸入目錄路徑和 Ghidra 路徑。
2. 驗證指定路徑下的 Ghidra headless analyzer 是否存在。
3. 設定用於儲存提取檔案的輸出目錄。
4. 設定日誌記錄設定。
5. 產生並行處理的參數列表。
6. 執行並行處理以提取地址和 opcode 資訊，並將結果儲存為 CSV 檔案。
7. 清理臨時 `ghidra_projects` 目錄。

## 結論

這個 Python 工具提供了一種方便的方式，使用 Ghidra 強大的反組譯引擎從二進位檔案中提取地址和 opcode 資訊，並將結果儲存為 CSV 檔案。它利用 Ghidra 的 headless 模式進行自動化處理，並使用並行處理加快提取速度。

此工具需要安裝 Ghidra 和 Python 套件 `pandas` 與 `tqdm`，並可透過命令列介面使用。提取的 CSV 檔案將儲存在與輸入目錄同層級的目錄中，命名為 `<binary_directory>_disassemble`。輸出目錄將包含組織到子目錄中的提取 CSV 檔案，以及提取和計時日誌檔案。

透過使用此工具，您可以輕鬆分析二進位檔案，並獲得有價值的地址和 opcode 資訊，以供進一步研究和分析。

## 參考資料

此工具使用 Ghidra 和幾個與 Python 3.x 相容的 Python 程式庫。以下是參考資料和其他資源：

1. **Ghidra**：由美國國家安全局 (NSA) 開發的軟體逆向工程框架。官方網站和文件：[Ghidra](https://ghidra-sre.org/)。

2. **os、time 和 shutil**：用於作業系統互動、時間相關功能和檔案操作的內建 Python 程式庫。更多詳細資訊請參閱官方 Python 文件：[Python 標準程式庫](https://docs.python.org/zh-tw/3/library/)。

3. **subprocess**：用於產生新程序和與外部程式互動的標準 Python 程式庫。文件可在以下網址取得：[Subprocess](https://docs.python.org/zh-tw/3/library/subprocess.html)。

4. **logging 和 argparse**：用於日誌記錄和解析命令列參數的標準 Python 程式庫。文件可在以下網址取得：[Logging](https://docs.python.org/zh-tw/3/library/logging.html) 和 [Argparse](https://docs.python.org/zh-tw/3/library/argparse.html)。

5. **pandas**：功能強大的 Python 資料操作和分析程式庫。官方文件和使用者指南：[Pandas 文件](https://pandas.pydata.org/)。

6. **tqdm**：用於在 Python 迴圈中添加進度條的程式庫。儲存庫和文件：[tqdm GitHub](https://github.com/tqdm/tqdm)。

7. **concurrent.futures**：用於並行執行的 Python 程式庫。文件可在以下網址取得：[Concurrent.futures](https://docs.python.org/zh-tw/3/library/concurrent.futures.html)。

8. **Ghidra Python API**：Ghidra Python 腳本功能的文件，包括此工具中使用的 `DisassembleCommand` 和其他 API：[Ghidra API](https://ghidra.re/ghidra_docs/api/)。

這些參考資料為理解此 opcode 提取工具開發中使用的工具和程式庫提供了基礎。
