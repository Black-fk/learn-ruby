# **Scanner Básico de Segurança em Ruby - Documentação Completa**

Este documento explica detalhadamente um scanner de segurança básico escrito em Ruby, que realiza verificações de portas abertas, diretórios web e testes básicos de vulnerabilidades (SQLi e XSS).

---

## **1. Estrutura Geral do Código**
O scanner está organizado em uma única classe `BasicScanner` com os seguintes componentes principais:

| Método/Funcionalidade | Descrição |
|-----------------------|-----------|
| `initialize` | Configura opções padrão e analisa argumentos da CLI |
| `parse_options` | Processa argumentos de linha de comando (`-h`, `-p`, etc.) |
| `validate_options` | Valida se o host alvo foi fornecido |
| `run` | Método principal que executa todas as verificações |
| `scan_ports` | Verifica portas abertas no host alvo |
| `scan_directories` | Testa diretórios comuns em servidores web |
| `test_basic_vulnerabilities` | Inicia testes de SQLi e XSS |
| `test_sql_injection` | Realiza testes básicos de SQL injection |
| `test_xss` | Realiza testes básicos de XSS |

---

## **2. Dependências e Bibliotecas Utilizadas**
```ruby
require 'socket'       # Para verificação de portas (TCP)
require 'net/http'     # Para requisições HTTP (diretórios, SQLi, XSS)
require 'optparse'     # Para análise de argumentos da CLI
require 'timeout'      # Para definir timeout em conexões
```
- **`socket`**: Usado para verificar portas TCP abertas.
- **`net/http`**: Realiza requisições HTTP para testar diretórios e vulnerabilidades.
- **`optparse`**: Facilita a criação de um parser de argumentos de linha de comando.
- **`timeout`**: Define um tempo máximo para tentativas de conexão.

---

## **3. Configuração Inicial e Argumentos da CLI**
### **Opções Padrão**
```ruby
@options = {
  host: nil,                      # Host alvo (obrigatório)
  ports: [80, 443, 8080, 22, 21], # Portas padrão para scan
  wordlist: ['admin', 'login', 'wp-admin', 'backup', 'config'], # Diretórios comuns
  timeout: 5                      # Tempo limite para conexões (segundos)
}
```

### **Parser de Argumentos (`parse_options`)**
| Argumento | Descrição | Exemplo |
|-----------|-----------|---------|
| `-h`, `--host` | Define o host alvo | `./scanner.rb -h exemplo.com` |
| `-p`, `--ports` | Lista de portas para scanear | `-p 80,443,8080` |
| `-w`, `--wordlist` | Lista de diretórios para testar | `-w admin,login,test` |
| `-t`, `--timeout` | Tempo limite para conexões | `-t 3` |

---

## **4. Funcionalidades do Scanner**
### **A. Scanner de Portas (`scan_ports`)**
Verifica se as portas especificadas estão abertas no host alvo.

**Método:**
```ruby
def scan_ports
  @options[:ports].each do |port|
    begin
      Timeout.timeout(@options[:timeout]) do
        socket = TCPSocket.new(@options[:host], port)
        puts "[+] Porta #{port}/tcp aberta"
        socket.close
      end
    rescue Timeout::Error
      puts "[-] Timeout na porta #{port}"
    rescue Errno::ECONNREFUSED
      # Porta fechada (não imprime nada)
    rescue => e
      puts "[-] Erro ao verificar porta #{port}: #{e.message}"
    end
  end
end
```

**Comportamento:**
- Tenta estabelecer uma conexão TCP em cada porta.
- Se a conexão for bem-sucedida, a porta está aberta.
- Se falhar com `ECONNREFUSED`, a porta está fechada.
- Se ocorrer timeout, considera a porta como filtrada/inacessível.

---

### **B. Scanner de Diretórios (`scan_directories`)**
Testa a existência de diretórios comuns em servidores web.

**Método:**
```ruby
def scan_directories
  http = Net::HTTP.new(@options[:host], 80)
  http.open_timeout = @options[:timeout]
  http.read_timeout = @options[:timeout]

  @options[:wordlist].each do |dir|
    begin
      response = http.request(Net::HTTP::Get.new("/#{dir}"))
      
      case response.code.to_i
      when 200..299
        puts "[+] Diretório encontrado: /#{dir} (HTTP #{response.code})"
      when 401, 403
        puts "[!] Diretório protegido: /#{dir} (HTTP #{response.code})"
      end
    rescue => e
      puts "[-] Erro ao verificar /#{dir}: #{e.message}"
    end
  end
end
```

**Comportamento:**
- Envia uma requisição `GET` para cada diretório na wordlist.
- Se retornar `200-299`, o diretório existe.
- Se retornar `401` ou `403`, o diretório existe mas está protegido.
- Se falhar, registra o erro.

---

### **C. Teste de SQL Injection (`test_sql_injection`)**
Verifica vulnerabilidades básicas de SQLi em formulários de login.

**Payloads testados:**
```ruby
payloads = [
  "' OR '1'='1",   # SQLi clássico
  "admin'--",       # Comentando o resto da query
  "1' OR 1=1#"      # Outra variação comum
]
```

**Método:**
```ruby
def test_sql_injection
  uri = URI("http://#{@options[:host]}/login.php")
  http = Net::HTTP.new(uri.host, uri.port)
  http.open_timeout = @options[:timeout]
  http.read_timeout = @options[:timeout]

  payloads.each do |payload|
    params = { 'username' => payload, 'password' => 'test' }
    response = http.post(uri.path, URI.encode_www_form(params))

    if response.body.downcase.include?('bem-vindo') || 
       response.body.downcase.include?('welcome') || 
       response['location']&.include?('dashboard')
      puts "[!] Possível SQLi com payload: #{payload}"
    end
  end
end
```

**Lógica de Detecção:**
- Se a resposta contém "bem-vindo", "welcome" ou redireciona para um dashboard, há indício de SQLi.

---

### **D. Teste de XSS (`test_xss`)**
Verifica se entradas são refletidas sem sanitização.

**Payloads testados:**
```ruby
payloads = [
  "<script>alert('XSS')</script>",  # XSS básico
  "<img src=x onerror=alert(1)>",    # XSS via atributo HTML
  "\"><svg/onload=alert(1)>"         # XSS via tag SVG
]
```

**Método:**
```ruby
def test_xss
  uri = URI("http://#{@options[:host]}/search.php")
  http = Net::HTTP.new(uri.host, uri.port)
  http.open_timeout = @options[:timeout]
  http.read_timeout = @options[:timeout]

  payloads.each do |payload|
    response = http.get("#{uri.path}?q=#{URI.encode_www_form_component(payload)}")

    if response.body.include?(payload)
      puts "[!] Possível XSS com payload: #{payload}"
    end
  end
end
```

**Lógica de Detecção:**
- Se o payload aparece na resposta sem sanitização, há risco de XSS.

---

## **5. Como Executar o Scanner**
### **Comandos Básicos**
```bash
# Scan básico em um host
./scanner.rb -h exemplo.com

# Scan com portas personalizadas
./scanner.rb -h exemplo.com -p 80,443,8080

# Scan com wordlist personalizada
./scanner.rb -h exemplo.com -w admin,test,backup

# Definir timeout menor (3 segundos)
./scanner.rb -h exemplo.com -t 3
```

### **Saída Esperada**
```
[+] Iniciando scan no alvo: exemplo.com
[+] Hora de início: 2023-05-23 20:30:00

[+] Verificando portas abertas...
[+] Porta 80/tcp aberta
[+] Porta 443/tcp aberta

[+] Procurando diretórios comuns...
[+] Diretório encontrado: /admin (HTTP 200)
[!] Diretório protegido: /config (HTTP 403)

[+] Testando vulnerabilidades básicas...
[!] Possível SQLi com payload: ' OR '1'='1
[!] Possível XSS com payload: <script>alert('XSS')</script>

[+] Scan concluído em: 2023-05-23 20:32:15
```

---

## **6. Melhorias Futuras**
1. **Adicionar suporte a HTTPS** (usando `Net::HTTP` com SSL).
2. **Implementar multi-threading** para scans mais rápidos.
3. **Adicionar mais testes** (ex.: CSRF, File Inclusion).
4. **Gerar relatórios em HTML/JSON** para análise posterior.
5. **Integrar com ferramentas como Burp Suite** via API.

---

## **7. Considerações de Segurança**
- ⚠️ **Use apenas em sistemas autorizados**.
- 🔒 **Não use para atividades maliciosas**.
- 📜 **Este scanner é para fins educacionais**.

---

**Repositório GitHub:** [https://github.com/seuuser/ruby-scanner](https://github.com/seuuser/ruby-scanner)  
**Licença:** MIT  

**Dúvidas?** Contribuições são bem-vindas! 🚀
