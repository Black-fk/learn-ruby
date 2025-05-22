# **Aulão de Ruby para Pentest v1**  
**(Do Zero à Programação Funcional em 4 Aulas)**  

---

## **Aula 1: Introdução à Sintaxe Ruby**  
**Objetivo:** Familiarizar com a linguagem e lógica básica  

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
# **Aula 1: Introdução ao Ruby para Segurança da Informação - Roteiro Detalhado**

---

## **Aulão de Ruby para Pentest v2**
**Objetivo:** Apresentar o curso e despertar interesse.

**Atividades:**
- [ ] Breve introdução sobre Ruby (linguagem dinâmica, orientada a objetos)
- [ ] Por que Ruby para segurança? 
  - Linguagem favorita para scripts rápidos
  - Usada no Metasploit Framework
  - Sintaxe limpa e expressiva
- [ ] Exemplo real: Mostrar um script simples de verificação de portas

**Slide de Apoio:**  
*"Ruby: A linguagem que alimenta ferramentas profissionais de pentesting"*

---

## **2. Configuração do Ambiente (15 minutos)**
**Objetivo:** Todos com ambiente funcionando.

**Passo a Passo:**
1. Instalação no Linux:
   ```bash
   sudo apt update && sudo apt install ruby -y
   ```
2. Verificação:
   ```bash
   ruby -v
   ```
3. Teste no IRB (Interactive Ruby Shell):
   ```ruby
   puts "Hello, Hackers!"
   ```

**Atividade Prática:**  
- Todos executam `ruby -v` e testam um comando simples no IRB

**Dica:**  
*Mostrar atalhos do IRB (Ctrl+C para sair, Tab para autocompletar)*

---

## **3. Fundamentos de Ruby (30 minutos)**
**Objetivo:** Ensinar sintaxe essencial para scripts de segurança.

**Tópicos:**
1. **Variáveis e Tipos Básicos**
   ```ruby
   alvo = "192.168.1.1"
   portas = [80, 443, 22, 3389]
   ```
   
2. **Estruturas de Controle**
   ```ruby
   # If/Else
   if porta == 80
     puts "Serviço HTTP"
   end

   # Loops
   3.times { puts "Testando..." }
   ```

3. **Métodos**
   ```ruby
   def scan_port(ip, porta)
     # Lógica aqui
   end
   ```

**Exercício Interativo:**  
*Perguntar: "Como criar um array com portas comuns?" e deixar alunos tentarem no IRB*

---

## **4. Hands-on: Scanner de Portas (30 minutos)**
**Objetivo:** Primeiro script funcional.

**Código Guiado:**
```ruby
#!/usr/bin/env ruby
# encoding: UTF-8

require 'socket'
require 'net/http'
require 'optparse'
require 'timeout'

class BasicScanner
  def initialize
    @options = {
      host: nil,
      ports: [80, 443, 8080, 22, 21],
      wordlist: ['admin', 'login', 'wp-admin', 'backup', 'config'],
      timeout: 5
    }
    parse_options
    validate_options
  end

  def run
    puts "\n[+] Iniciando scan no alvo: #{@options[:host]}"
    puts "[+] Hora de início: #{Time.now}\n"

    scan_ports
    scan_directories
    test_basic_vulnerabilities

    puts "\n[+] Scan concluído em: #{Time.now}"
  end

  private

  def parse_options
    OptionParser.new do |opts|
      opts.banner = "Uso: #{$0} [opções]"

      opts.on("-h", "--host HOST", "Host alvo (IP ou domínio)") do |h|
        @options[:host] = h
      end

      opts.on("-p", "--ports PORT1,PORT2", Array, "Portas para scanear (padrão: 80,443,8080,22,21)") do |p|
        @options[:ports] = p.map(&:to_i)
      end

      opts.on("-w", "--wordlist WORD1,WORD2", Array, "Lista de diretórios para testar") do |w|
        @options[:wordlist] = w
      end

      opts.on("-t", "--timeout SECONDS", Integer, "Tempo limite para conexões (padrão: 5)") do |t|
        @options[:timeout] = t
      end
    end.parse!
  end

  def validate_options
    unless @options[:host]
      puts "[-] Você deve especificar um host alvo"
      exit(1)
    end
  end

  def scan_ports
    puts "\n[+] Verificando portas abertas..."

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
        # Porta fechada
      rescue => e
        puts "[-] Erro ao verificar porta #{port}: #{e.message}"
      end
    end
  end

  def scan_directories
    puts "\n[+] Procurando diretórios comuns..."

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

  def test_basic_vulnerabilities
    puts "\n[+] Testando vulnerabilidades básicas..."

    test_sql_injection
    test_xss
  end

  def test_sql_injection
    puts "\n[+] Testando SQL injection básico..."

    payloads = [
      "' OR '1'='1",
      "admin'--",
      "1' OR 1=1#"
    ]

    uri = URI("http://#{@options[:host]}/login.php")
    http = Net::HTTP.new(uri.host, uri.port)
    http.open_timeout = @options[:timeout]
    http.read_timeout = @options[:timeout]

    payloads.each do |payload|
      begin
        params = { 'username' => payload, 'password' => 'test' }
        response = http.post(uri.path, URI.encode_www_form(params))

        if response.body.downcase.include?('bem-vindo') || 
           response.body.downcase.include?('welcome') || 
           response['location']&.include?('dashboard')
          puts "[!] Possível SQLi com payload: #{payload}"
        end
      rescue => e
        puts "[-] Erro ao testar SQLi: #{e.message}"
      end
    end
  end

  def test_xss
    puts "\n[+] Testando XSS básico..."

    payloads = [
      "<script>alert('XSS')</script>",
      "<img src=x onerror=alert(1)>",
      "\"><svg/onload=alert(1)>"
    ]

    uri = URI("http://#{@options[:host]}/search.php")
    http = Net::HTTP.new(uri.host, uri.port)
    http.open_timeout = @options[:timeout]
    http.read_timeout = @options[:timeout]

    payloads.each do |payload|
      begin
        response = http.get("#{uri.path}?q=#{URI.encode_www_form_component(payload)}")

        if response.body.include?(payload)
          puts "[!] Possível XSS com payload: #{payload}"
        end
      rescue => e
        puts "[-] Erro ao testar XSS: #{e.message}"
      end
    end
  end
end

if __FILE__ == $0
  scanner = BasicScanner.new
  scanner.run
end
```

**Passo a Passo:**
1. Explicar `require 'socket'` (biblioteca padrão)
2. Mostrar como `TCPSocket` funciona
3. Explicar tratamento de erros com `begin/rescue`

**Desafio Opcional:**  
*"Quem consegue modificar para verificar um range de portas (ex: 1-100)?"*

---

## **5. Caso Real: Análise de Logs (15 minutos)**
**Objetivo:** Mostrar aplicação prática.

**Exemplo:**
```ruby
log = "2023-01-01 10:00:45 - Tentativa de login falho: admin
       2023-01-01 10:01:12 - Tentativa de login falho: root"

# Contar tentativas falhas
tentativas = log.scan(/login falho/).count
puts "Alert: #{tentativas} tentativas de invasão!"
```

**Discussão:**  
*Como isso seria útil em um SIEM?*

---

## **6. Encerramento (10 minutos)**
**Recapitulação:**
1. Sintaxe básica de Ruby
2. Primeiro script de rede
3. Aplicações em segurança

**Próximos Passos:**
- Praticar modificações no scanner
- Explorar a documentação Ruby

**Q&A:**  
*Responder dúvidas e sugerir exercícios extras*

---

**Material Complementar:**
- [Try Ruby Online](https://try.ruby-lang.org/)
- [Ruby em 15 Minutos](https://www.ruby-lang.org/pt/documentation/quickstart/)

**Tarefa de Casa:**  
*Criar um script que:*
1. Pede um domínio ao usuário
2. Verifica se as portas 80 e 443 estão abertas
3. Retorna "Possível servidor web" se alguma estiver aberta

---

**Dica para Instrutor:**  
- Use analogias (ex: portas como portas de um shopping)
- Relacione sempre com cenários reais de segurança
- Mantenha o ritmo interativo com perguntas

# **Aula 2: Análise de Vulnerabilidades Web com Ruby - Roteiro Detalhado**

## **1. Abertura da Aula (15 minutos)**
**Objetivo:** Contextualizar análise web e introduzir ferramentas.

**Atividades:**
- [ ] Introdução a vulnerabilidades web (OWASP Top 10)
- [ ] Por que automatizar com Ruby?
  - Flexibilidade para criar testes customizados
  - Integração com outras ferramentas
- [ ] Demonstração rápida de um scanner de diretórios

**Slide de Apoio:**  
*"Automatizando testes web: Do reconhecimento à exploração"*

---

## **2. Fundamentos de HTTP em Ruby (25 minutos)**
**Objetivo:** Dominar requisições web básicas.

**Tópicos Práticos:**
1. **Requisições GET**
```ruby
require 'net/http'
response = Net::HTTP.get_response(URI('http://exemplo.com/admin'))
puts response.code  # => "200"
```

2. **Enviando POST com parâmetros**
```ruby
uri = URI('http://exemplo.com/login')
res = Net::HTTP.post_form(uri, 'username' => 'admin', 'password' => '12345')
puts res.body
```

**Exercício Dirigido:**  
*Modificar o código para:*
- Enviar um header User-Agent personalizado
- Lidar com redirecionamentos (código 301/302)

---

## **3. Web Scraping para Reconhecimento (30 minutos)**
**Objetivo:** Extrair informações estratégicas.

**Código Guiado (Nokogiri):**
```ruby
require 'nokogiri'
require 'open-uri'

doc = Nokogiri::HTML(URI.open("http://exemplo.com"))
# Extrair todos os formulários
doc.css('form').each do |form|
  puts "Formulário encontrado: Ação #{form['action']}"
end
```

**Caso Real:**  
*Identificar:*
- Campos de login
- Endpoints API expostos
- Comentários HTML com informações sensíveis

---

## **4. Fuzzing Básico (35 minutos)**
**Objetivo:** Automatizar testes de injeção.

**Exemplo Prático (SQLi Testing):**
```ruby
payloads = ["' OR '1'='1", "admin'--", "' UNION SELECT null,username,password FROM users--"]
payloads.each do |payload|
  uri = URI("http://exemplo.com/search?q=#{URI.encode_www_form_component(payload)}")
  res = Net::HTTP.get(uri)
  puts "Vulnerável com #{payload}" if res.include?("error in your SQL syntax")
end
```

**Discussão Ética:**  
*Quando parar o teste? Como documentar achados?*

---

## **5. Encerramento (15 minutos)**
**Próximos Passos:**  
- Introduzir autenticação em testes
- Trabalhar com sessões e cookies

**Tarefa:**  
*Criar um script que:*
1. Testa 3 URLs contra XSS básico
2. Gera um relatório em formato CSV

---

# **Aula 3: Exploração Avançada - Roteiro Detalhado**

## **1. Warm-up: Revisão Rápida (10 minutos)**
**Atividade Interativa:**  
*"Qual foi o desafio mais interessante da aula 2?"*

---

## **2. Sniffing de Rede (40 minutos)**
**Demo com PacketFu:**
```ruby
require 'packetfu'

def packet_capture
  cap = PacketFu::Capture.new(iface: 'eth0', start: true)
  cap.stream.each do |pkt|
    packet = PacketFu::Packet.parse(pkt)
    next unless packet.is_tcp?
    puts "Packet: #{packet.ip_saddr}:#{packet.tcp_sport} -> #{packet.ip_daddr}:#{packet.tcp_dport}"
  end
end
```

**Exercício Prático:**  
*Filtrar apenas pacotes HTTP e extrair URLs*

---

## **3. Quebra de Hashes (45 minutos)**
**Código Didático:**
```ruby
require 'digest'

def crack_hash(hash, wordlist)
  File.foreach(wordlist) do |password|
    password.chomp!
    if Digest::SHA256.hexdigest(password) == hash
      return password
    end
  end
  nil
end

# Uso:
crack_hash("5e8848...", "rockyou.txt")
```

**Otimização:**  
*Adicionar progress bar e salt detection*

---

## **4. Construindo um Exploit Simples (50 minutos)**
**Exemplo Didático (Buffer Overflow Simulado):**
```ruby
# Gerador de payload
def exploit
  junk = "A" * 1024  # Preenche o buffer
  eip = "\x42\x42\x42\x42"  # Sobrescreve EIP
  payload = junk + eip
  send_to_vulnerable_app(payload)
end
```

**Discussão:**  
*Como adaptar para casos reais?*

---

## **5. Encerramento do Módulo (15 minutos)**
**Roadmap Avançado:**  
- Integração com Metasploit
- Análise de malware em Ruby

**Projeto Final:**  
*Desenvolver uma ferramenta completa que:*
1. Faz reconhecimento
2. Testa vulnerabilidades
3. Gera relatórios

**Material Extra:**  
[Ruby Security Projects no GitHub]
