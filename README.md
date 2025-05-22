# **Roteiro Básico para Ensinar Ruby**  
**(Do Zero à Programação Funcional em 4 Aulas)**  

---

## **Aula 1: Introdução à Sintaxe Ruby**  
# **Pesquisa Resumida sobre Ruby**  

## **1. Visão Geral**  
Ruby é uma linguagem de programação **interpretada**, **dinâmica** e **orientada a objetos**, criada em **1995** por **Yukihiro Matsumoto** ("Matz"). Destaca-se pela sintaxe elegante e produtividade, sendo amplamente usada em desenvolvimento web, automação e segurança da informação.  

## **2. Características Principais**  
- **Legível e expressiva** (prioriza a simplicidade)  
- **Orientação a objetos pura** (tudo é um objeto)  
- **Tipagem dinâmica e forte**  
- **Gerenciamento automático de memória**  
- **Ecossistema rico** (RubyGems, frameworks como Rails)  

## **3. Aplicações em Segurança**  
- Automação de testes de invasão (Metasploit, WPScan)  
- Análise de vulnerabilidades web (SQLi, XSS)  
- Processamento de logs e dados de segurança  

## **4. Vantagens**  
✔ Fácil aprendizado  
✔ Alta produtividade  
✔ Comunidade ativa  

## **5. Limitações**  
✖ Performance inferior a linguagens como C ou Go  
✖ Menos popular que Python para scripts gerais  

## **6. Curiosidade**  
Ruby foi projetado para ser "natural, não simples", equilibrando flexibilidade e usabilidade. Seu sucesso em segurança deve-se à integração com ferramentas como o Metasploit Framework.  

**"Ruby faz você escrever menos código para fazer mais."** — Filosofia da linguagem.

### **1. Configuração (15 min)**  
- Instalação do Ruby (Linux/Windows/Mac)  
- Uso do IRB (Interactive Ruby Shell)  
- Primeiro programa:  
  ```ruby
  puts "Olá, mundo!"  
  ```

### **2. Fundamentos (45 min)**  
- **Variáveis e Tipos**:  
  ```ruby
  nome = "Alice"       # String  
  idade = 30           # Integer  
  preco = 19.99       # Float  
  ativo = true        # Boolean  
  ```

- **Operadores Básicos**:  
  ```ruby
  soma = 5 + 3         # 8  
  texto = "Oi " + "Ruby" # Concatenação  
  ```

- **Entrada de Usuário**:  
  ```ruby
  puts "Qual seu nome?"  
  nome = gets.chomp  
  ```

### **3. Exercício Prático (30 min)**  
**Calculadora Simples**:  
```ruby
puts "Digite um número:"  
num1 = gets.to_f  
puts "Digite outro número:"  
num2 = gets.to_f  
puts "Soma: #{num1 + num2}"  
```

---

## **Aula 2: Estruturas de Controle e Coleções**  
**Objetivo:** Dominar condicionais e loops  

### **1. Condicionais (30 min)**  
- **If/Else**:  
  ```ruby
  if idade >= 18  
    puts "Adulto"  
  else  
    puts "Menor"  
  end  
  ```

- **Case/When**:  
  ```ruby
  case nota  
  when 9..10 then "A"  
  when 7..8  then "B"  
  else "Reprovado"  
  end  
  ```

### **2. Arrays e Hashes (40 min)**  
- **Array**:  
  ```ruby
  frutas = ["maçã", "banana", "laranja"]  
  frutas[0]  # "maçã"  
  ```

- **Hash**:  
  ```ruby
  pessoa = { nome: "Carlos", idade: 25 }  
  pessoa[:nome]  # "Carlos"  
  ```

### **3. Loops (30 min)**  
- **While**:  
  ```ruby
  i = 0  
  while i < 5  
    puts i  
    i += 1  
  end  
  ```

- **Each**:  
  ```ruby
  (1..5).each { |n| puts n }  
  ```

### **Exercício:**  
**Lista de Compras**:  
```ruby
itens = []  
loop do  
  puts "Digite um item (ou 'sair'):"  
  item = gets.chomp  
  break if item == "sair"  
  itens << item  
end  
puts "Lista: #{itens.join(", ")}"  
```

---

## **Aula 3: Métodos e Classes**  
**Objetivo:** Introduzir programação orientada a objetos  

### **1. Métodos (40 min)**  
- **Definição**:  
  ```ruby
  def saudacao(nome)  
    "Olá, #{nome}!"  
  end  
  puts saudacao("Maria")  
  ```

- **Parâmetros Default**:  
  ```ruby
  def somar(a, b = 10)  
    a + b  
  end  
  somar(5)  # 15  
  ```

### **2. Classes (50 min)**  
- **Classe Simples**:  
  ```ruby
  class Pessoa  
    attr_accessor :nome, :idade  

    def initialize(nome, idade)  
      @nome = nome  
      @idade = idade  
    end  

    def apresentar  
      "Me chamo #{@nome} e tenho #{@idade} anos."  
    end  
  end  

  pessoa1 = Pessoa.new("João", 30)  
  puts pessoa1.apresentar  
  ```

### **Exercício:**  
**Classe `ContaBancaria`**:  
```ruby
class ContaBancaria  
  attr_reader :saldo  

  def initialize(saldo_inicial = 0)  
    @saldo = saldo_inicial  
  end  

  def depositar(valor)  
    @saldo += valor  
  end  
end  
```

---

## **Aula 4: Tópicos Avançados**  
**Objetivo:** Explorar funcionalidades poderosas  

### **1. Blocos e Yield (30 min)**  
```ruby
def repetir(vezes)  
  vezes.times { yield }  
end  

repetir(3) { puts "Ruby!" }  
```

### **2. Módulos (30 min)**  
```ruby
module Matematica  
  def self.dobro(num)  
    num * 2  
  end  
end  

puts Matematica.dobro(4)  # 8  
```

### **3. Trabalhando com Arquivos (30 min)**  
```ruby
# Escrever  
File.write("arquivo.txt", "Conteúdo")  

# Ler  
puts File.read("arquivo.txt")  
```

### **Projeto Final:**  
**Sistema de Tarefas**:  
```ruby
class Tarefa  
  attr_accessor :descricao, :concluida  

  def initialize(descricao)  
    @descricao = descricao  
    @concluida = false  
  end  
end  

tarefas = []  
tarefas << Tarefa.new("Aprender Ruby")  
```

---

## **Fluxo Recomendado**  
1. **Teoria** → 2. **Exemplos ao Vivo** → 3. **Exercícios Guiados** → 4. **Desafios Práticos**  

**Dicas para Instrutor**:  
- Use analogias (ex: classes como "receitas de bolo")  
- Compare com outras linguagens (Python/JavaScript)  
- Incentive a leitura da [Documentação Ruby](https://ruby-doc.org/)  

**Material Extra**:  
- [Ruby em 15 Minutos](https://www.ruby-lang.org/pt/documentation/quickstart/)  
- [Exercícios no Codewars](https://www.codewars.com/?language=ruby)
- 
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
