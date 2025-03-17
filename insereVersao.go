package main

import (
	"bufio"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
	"strings"
	"math/rand"
	"strconv"
	"syscall"
	"unsafe"

	_ "github.com/waldurbas/firebirdsql"
)

func crypt(action string, src string) string {
	key := "YUQL23KL23DF90WI5E1JAS467NMCXXL6JAOAUWWMCL0AOMM4A4VZYW9KHJUI2347EJHJKDF3424SKLK3LAKDJSL9RTIKJ"
	var dest strings.Builder
	keyLen := len(key)
	keyPos := 0
	range_ := 256

	if strings.ToUpper(action) == "C" {
		rand.Seed(time.Now().UnixNano())
		offset := rand.Intn(range_)
		dest.WriteString(fmt.Sprintf("%02X", offset))

		for i := 0; i < len(src); i++ {
			srcAsc := (int(src[i]) + offset) % 255
			keyPos++
			if keyPos > keyLen {
				keyPos = 1
			}
			srcAsc ^= int(key[keyPos-1])
			dest.WriteString(fmt.Sprintf("%02X", srcAsc))
			offset = srcAsc
		}
	} else if strings.ToUpper(action) == "D" {
		if len(src) < 2 {
			fmt.Println("Erro: entrada criptografada inválida ou vazia.")
			return ""
		}

		offset, _ := strconv.ParseInt(src[:2], 16, 64)
		srcPos := 2

		for srcPos < len(src) {
			srcAsc, _ := strconv.ParseInt(src[srcPos:srcPos+2], 16, 64)
			keyPos++
			if keyPos > keyLen {
				keyPos = 1
			}
			tmpSrcAsc := srcAsc ^ int64(key[keyPos-1])
			if tmpSrcAsc <= offset {
				tmpSrcAsc = 255 + tmpSrcAsc - offset
			} else {
				tmpSrcAsc -= offset
			}
			dest.WriteByte(byte(tmpSrcAsc))
			offset = srcAsc
			srcPos += 2
		}
	}

	return dest.String()
}

func lerArquivoIni(filename string) (string, string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", "", fmt.Errorf("erro ao abrir o arquivo: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var nomeCriptografado, caminhoCriptografado string

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "NOME=") {
			nomeCriptografado = strings.TrimPrefix(line, "NOME=")
		} else if strings.HasPrefix(line, "CAMINHO=") {
			caminhoCriptografado = strings.TrimPrefix(line, "CAMINHO=")
		}

		if nomeCriptografado != "" && caminhoCriptografado != "" {
			break
		}
	}

	if err := scanner.Err(); err != nil {
		return "", "", fmt.Errorf("erro ao ler o arquivo: %v", err)
	}

	return nomeCriptografado, caminhoCriptografado, nil
}

type VS_FIXEDFILEINFO struct {
	Signature        uint32
	StrucVersion     uint32
	FileVersionMS    uint32
	FileVersionLS    uint32
	ProductVersionMS uint32
	ProductVersionLS uint32
	FileFlagsMask    uint32
	FileFlags        uint32
	FileOS           uint32
	FileType         uint32
	FileSubtype      uint32
	FileDateMS       uint32
	FileDateLS       uint32
}


func GetFileVersion(filePath string) (string, error) {
	lib := syscall.NewLazyDLL("version.dll")
	getFileVersionInfoSize := lib.NewProc("GetFileVersionInfoSizeW")
	getFileVersionInfo := lib.NewProc("GetFileVersionInfoW")
	verQueryValue := lib.NewProc("VerQueryValueW")

	filePathPtr, err := syscall.UTF16PtrFromString(filePath)
	if err != nil {
		return "", err
	}

	// Obtém o tamanho necessário para armazenar as informações da versão
	size, _, _ := getFileVersionInfoSize.Call(uintptr(unsafe.Pointer(filePathPtr)), 0)
	if size == 0 {
		return "", fmt.Errorf("falha ao obter tamanho das informações da versão")
	}

	// Cria um buffer para armazenar as informações da versão
	data := make([]byte, size)

	// Obtém as informações da versão
	ok, _, _ := getFileVersionInfo.Call(
		uintptr(unsafe.Pointer(filePathPtr)),
		0,
		uintptr(size),
		uintptr(unsafe.Pointer(&data[0])))

	if ok == 0 {
		return "", fmt.Errorf("falha ao obter informações da versão")
	}

	// Obtém o ponteiro para a estrutura VS_FIXEDFILEINFO
	var verPtr *VS_FIXEDFILEINFO
	var verLen uint32
	subBlock, _ := syscall.UTF16PtrFromString(`\`)
	ok, _, _ = verQueryValue.Call(
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(unsafe.Pointer(subBlock)),
		uintptr(unsafe.Pointer(&verPtr)),
		uintptr(unsafe.Pointer(&verLen)),
	)
	if ok == 0 {
		return "", nil
	}

	// Converte o ponteiro para a estrutura VS_FIXEDFILEINFO
	fixedFileInfo := (*VS_FIXEDFILEINFO)(unsafe.Pointer(verPtr))

	// Extrai a versão do arquivo
	major := fixedFileInfo.FileVersionMS >> 16
	minor := fixedFileInfo.FileVersionMS & 0xFFFF
	build := fixedFileInfo.FileVersionLS >> 16
	revision := fixedFileInfo.FileVersionLS & 0xFFFF

	version := fmt.Sprintf("%d.%d.%d.%d", major, minor, build, revision)
	return version, nil
}


func main() {
	nomeCriptografado, caminhoCriptografado, err := lerArquivoIni("caminhobd.ini")
	if err != nil {
		fmt.Println(err)
		return
	}

	nome := crypt("D", nomeCriptografado)
	caminho := crypt("D", caminhoCriptografado)



	// Mensagem inicial
	fmt.Println("Programa de inserção de aplicativos no banco de dados Firebird")
	time.Sleep(2 * time.Second)
	
	connStr := "sysdba:masterkey@" + nome + ":3050/" + caminho
	db, err := sql.Open("firebirdsql", connStr)
	if err != nil {
		handleError("Erro ao conectar ao banco:", err)
		return
	}
	defer db.Close()

	if nome != "localhost" {
		handleError("Esse terminal não é o servidor. Uso exclusivo no servidor", err)
		return
	}

	// Verificar e criar a tabela se não existir
	if err := verificaTabela(db); err != nil {
		handleError("Erro ao verificar/criar a tabela:", err)
		return
	}

	tipoLoja, err := getTipoLoja(db)
	if err != nil {
		handleError("Erro ao verificar o tipo_loja na tabela PARAMETROS:", err)
		return
	}
	arquivos := []struct {
		nome  string
		index int
	}{
		{"FarmaxPDV.exe", 1},
		{"Gestor.exe", 2},
		{"Nfe.xtr", 3},


	}

	mensagens := map[string]string{
		"U": "Loja única identificada",
		"L": "Loja interligada identificada",
		"M": "Matriz identificada",
	}
	if msg, existe := mensagens[tipoLoja]; existe {
		fmt.Println(msg)
		fmt.Println("Aguarde inserindo os arquivos...")
		time.Sleep(3 * time.Second)

		for _, arquivo := range arquivos {
			if err := processFile(db, arquivo.nome, arquivo.index); err != nil {
				handleError(fmt.Sprintf("Erro ao processar o %s:", arquivo.nome), err)
				//return
			}
		}
	} else {
		fmt.Println("Tipo de loja não reconhecido. Nenhum arquivo será processado.")
	}

	fmt.Println("Pressione Enter para sair...")
	fmt.Scanln()
}

// verifica se a tabela existe e criá-la se necessário
func verificaTabela(db *sql.DB) error {
	queryCheck := `
		SELECT 1 
		FROM RDB$RELATIONS 
		WHERE RDB$RELATION_NAME = 'ARQUIVOS_FARMAX'
	`
	var exists int
	err := db.QueryRow(queryCheck).Scan(&exists)
	if err == sql.ErrNoRows {
		fmt.Println("Tabela ARQUIVOS_FARMAX não encontrada. Criando a tabela...")
		createTable := `
			CREATE TABLE ARQUIVOS_FARMAX (
				ID        INTEGER NOT NULL,
				NOME      VARCHAR(255),
				HASH_APP  VARCHAR(1000),
				PROGRAMA  BLOB SUB_TYPE BINARY SEGMENT SIZE 80,
				VERSAO	VARCHAR(20)
			)
		`
		_, err = db.Exec(createTable)
		if err != nil {
			return err
		}
		fmt.Println("Tabela ARQUIVOS_FARMAX criada com sucesso!")
	} else if err != nil {
		return err
	} else {
		fmt.Println("Tabela ARQUIVOS_FARMAX já existe no banco de dados.")
	}
	return nil
}

func getTipoLoja(db *sql.DB) (string, error) {
	query := "SELECT tipo_loja FROM PARAMETROS ROWS 1"
	var tipoLoja string
	err := db.QueryRow(query).Scan(&tipoLoja)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("tipo_loja não encontrado na tabela PARAMETROS")
	}
	return tipoLoja, err
}

// Processar o arquivo e inserir/atualizar no banco de dados
func processFile(db *sql.DB, filePath string, id int) error {
	fileName := getFileName(filePath)
	hash, err := calcHash(filePath)
	if err != nil {
		return err
	}
	version, _ := GetFileVersion(fileName)

	// Verificar se já existe um registro para o arquivo e obter o hash atual
	currentHash, exists, err := getHash(db, fileName)
	if err != nil {
		return err
	}

	if exists {
		if currentHash == hash {
			fmt.Printf("%s já está atualizado no banco de dados.\n", fileName)
			if fileName == "FarmaxPDV.exe" {
				query2 := "UPDATE PARAMETROS SET VERSAO_LOJA = ?"
				db.Exec(query2, version)
				//fmt.Println("Parametro versao_loja atualizado")
			}		
			if fileName == "Gestor.exe" {
				query2 := "UPDATE PARAMETROS SET VERSAO_GESTOR = ?"
				db.Exec(query2, version)
				//fmt.Println("Parametro versao_gestor atualizado")
			}
			var nfe = "Nfe.xtr"

			if nfe == "Nfe.xtr" {
				err := copyNFE(nfe)
				if err != nil {
					fmt.Println("Erro ao mover arquivo:", err)
			}
		}
			//time.Sleep(5 * time.Second)
			return nil
		}

		// Atualizar o registro existente com o novo hash e programa
		if err := updateFile(db, filePath,fileName, hash, version); err != nil {
			return err
		}
		fmt.Printf("%s foi atualizado com sucesso no banco de dados.\n", fileName)
		if fileName == "FarmaxPDV.exe" {
			query2 := "UPDATE PARAMETROS SET VERSAO_LOJA = ?"
			db.Exec(query2, version)
			//fmt.Println("Parametro versao_loja atualizado")
		}		
		if fileName == "Gestor.exe" {
			query2 := "UPDATE PARAMETROS SET VERSAO_GESTOR = ?"
			db.Exec(query2, version)
			//fmt.Println("Parametro versao_gestor atualizado")
		}	
		var nfe = "Nfe.xtr"

		if nfe == "Nfe.xtr" {
			err := copyNFE(nfe)
			if err != nil {
				fmt.Println("Erro ao mover arquivo:", err)
		}
	}
		
		//time.Sleep(5 * time.Second) // Aguardar 3 segundos após sucesso
	} else {
		// Inserir um novo registro se não existir
		if err := insertFile(db, filePath, id, fileName, hash, version); err != nil {
			return err
		}		
		}
		fmt.Printf("%s foi inserido com sucesso no banco de dados.\n", fileName)
		if fileName == "FarmaxPDV.exe" {
			query2 := "UPDATE PARAMETROS SET VERSAO_LOJA = ?"
			db.Exec(query2, version)
		}		
		if fileName == "Gestor.exe" {
			query2 := "UPDATE PARAMETROS SET VERSAO_GESTOR = ?"
			db.Exec(query2, version)
		}
		var nfe = "Nfe.xtr"

		if nfe == "Nfe.xtr" {
			err := copyNFE(nfe)
			if err != nil {
				fmt.Println("Erro ao mover arquivo:", err)
		}
	}	

		//time.Sleep(5 * time.Second) // Aguardar 3 segundos após sucesso
	return nil
}

// verificar se o arquivo já existe e obter o hash atual
func getHash(db *sql.DB, fileName string) (string, bool, error) {
	query := "SELECT HASH_APP FROM ARQUIVOS_FARMAX WHERE NOME = ?"
	var currentHash string
	err := db.QueryRow(query, fileName).Scan(&currentHash)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return currentHash, true, nil
}

// inserir o arquivo no banco
func insertFile(db *sql.DB, filePath string, id int, fileName, hash string, version string) error {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	query := "INSERT INTO ARQUIVOS_FARMAX (ID, NOME, HASH_APP, PROGRAMA, VERSAO) VALUES (?, ?, ?, ?, ?)"
	_, err = db.Exec(query, id, fileName, hash, content, version)
	
	return err
}

// atualizar o registro no banco
func updateFile(db *sql.DB, filePath string, fileName, hash string, version string) error {
	query := `
		UPDATE ARQUIVOS_FARMAX
		SET HASH_APP = ?, PROGRAMA = ?, VERSAO = ?
		WHERE NOME = ?
	`
	fileData, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("erro ao ler o arquivo: %v", err)
	}

	_, err = db.Exec(query, hash, fileData,version, fileName)
	
	if err != nil {
		return fmt.Errorf("erro ao atualizar o arquivo no banco de dados: %v", err)
	}
	return nil
}


// calcular o hash SHA-256 
func calcHash(filePath string) (string, error) {
	file, erro := os.Open(filePath)
	if erro != nil {
		return "", erro
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}



// obter o nome do arquivo a partir do caminho
func getFileName(filePath string) string {
	return filepath.Base(filePath)
}

// tratar erros
func handleError(message string, err error) {
	fmt.Println(message, err)
	fmt.Println("Pressione Enter para sair...")
	fmt.Scanln()
}

func copyNFE(fileName string) error {
    currentDir, err := os.Getwd()
    if err != nil {
        return fmt.Errorf("erro ao obter diretório atual: %v", err)
    }

    nfeFolder := filepath.Join(currentDir, "NFe")
    if _, err := os.Stat(nfeFolder); os.IsNotExist(err) {
        err := os.Mkdir(nfeFolder, os.ModePerm)
        if err != nil {
            return fmt.Errorf("erro ao criar a pasta NFe: %v", err)
        }
    }

    sourcePath := filepath.Join(currentDir, fileName)
    destPath := filepath.Join(nfeFolder, fileName)

    sourceFile, err := os.Open(sourcePath)
    if err != nil {
        return fmt.Errorf("erro ao abrir o arquivo de origem: %v", err)
    }
    defer sourceFile.Close()

    destinationFile, err := os.Create(destPath)
    if err != nil {
        return fmt.Errorf("erro ao criar o arquivo de destino: %v", err)
    }
    defer destinationFile.Close()

    _, err = io.Copy(destinationFile, sourceFile)
    if err != nil {
        return fmt.Errorf("erro ao copiar o arquivo: %v", err)
    }

    err = destinationFile.Sync()
    if err != nil {
        return fmt.Errorf("erro ao sincronizar o arquivo de destino: %v", err)
    }
   
    return nil
}
