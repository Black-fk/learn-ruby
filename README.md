# **Curso de Ruby para Segurança da Informação**  
**Roteiro Detalhado das Aulas + Códigos de Exemplo**  

---

## **Aula 1: Introdução ao Ruby e Automação Básica em Pentesting**  
**Duração:** 1h30  
**Objetivo:** Introduzir Ruby e criar scripts simples para reconhecimento em segurança.  

### **Roteiro:**  
1. **Introdução (15 min)**  
   - O que é Ruby e por que usar em segurança?  
   - Configuração do ambiente (`ruby -v`, `irb`).  

2. **Sintaxe Básica (30 min)**  
   - Variáveis, loops (`each`, `while`), métodos.  
   - Exemplo:  
     ```ruby
     # Loop para ver portas
     (1..10).each { |port| puts "Verificando porta #{port}" }
     ```  

3. **Manipulação de Strings e Arrays (20 min)**  
   - Extrair subdomínios de um log:  
     ```ruby
     log = "admin.site.com, backup.site.com"
     subdomains = log.split(", ")
     puts subdomains
     ```  

4. **Prática: Scanner de Portas (25 min)**  
   - Código completo (adaptável para IP externo):  
     ```ruby
     require 'socket'

     def port_scan(ip, start_port, end_port)
       (start_port..end_port).each do |port|
         begin
           socket = TCPSocket.new(ip, port)
           puts "[+] #{ip}:#{port} — ABERTA"
           socket.close
         rescue
           puts "[-] #{ip}:#{port} — FECHADA"
         end
       end
     end

     port_scan("127.0.0.1", 80, 100)
     ```  

---

## **Aula 2: Análise de Vulnerabilidades Web com Ruby**  
**Duração:** 2h  
**Objetivo:** Automar testes em aplicações web (fuzzing, scraping).  

### **Roteiro:**  
1. **Requisições HTTP (30 min)**  
   - GET/POST com `net/http`:  
     ```ruby
     uri = URI("http://alvo.com/login")
     response = Net::HTTP.post_form(uri, 'user' => 'admin', 'pass' => '123')
     puts response.body
     ```  

2. **Web Scraping (40 min)**  
   - Extrair links com `nokogiri`:  
     ```ruby
     require 'nokogiri'
     require 'open-uri'

     doc = Nokogiri::HTML(URI.open("http://alvo.com"))
     doc.css('a').each { |link| puts link['href'] }
     ```  

3. **Fuzzing de Parâmetros (50 min)**  
   - Testar SQL Injection:  
     ```ruby
     payloads = ["' OR '1'='1", "'--", "admin'#"]
     payloads.each do |payload|
       res = Net::HTTP.get_response(URI("http://alvo.com?search=#{payload}"))
       puts "Vulnerável!" if res.body.include?("error")
     end
     ```  

---

## **Aula 3: Exploração Avançada e Criação de Ferramentas**  
**Duração:** 2h30  
**Objetivo:** Desenvolver exploits e ferramentas customizadas.  

### **Roteiro:**  
1. **Sniffing de Rede (40 min)**  
   - Usando `packetfu` (instalar via `gem install packetfu`):  
     ```ruby
     require 'packetfu'

     def sniff_packets
       cap = PacketFu::Capture.new(iface: 'wlan0', start: true)
       cap.stream.each do |pkt|
         packet = PacketFu::Packet.parse(pkt)
         puts packet.inspect if packet.is_tcp?
       end
     end
     ```  

2. **Quebra de Hashes (50 min)**  
   - Força bruta em MD5:  
     ```ruby
     require 'digest'

     target_hash = "5f4dcc3b5aa765d61d8327deb882cf99" # hash de 'password'
     wordlist = ["123456", "password", "admin", "letmein"]

     wordlist.each do |word|
       if Digest::MD5.hexdigest(word) == target_hash
         puts "[+] Senha encontrada: #{word}"
         break
       end
     end
     ```  

3. **Exploit Básico (60 min)**  
   - Buffer Overflow simulado:  
     ```ruby
     buffer = "A" * 500
     puts "Exploit enviado: #{buffer}"
     # Simulação: Servidor crasha com 500 'A's
     ```  

---

## **Material Extra por Aula**  
- **Aula 1:**  
  - [Ruby em 20 Minutos](https://www.ruby-lang.org/pt/documentation/quickstart/)  
- **Aula 2:**  
  - [Nokogiri Tutorial](https://nokogiri.org/tutorials/)  
- **Aula 3:**  
  - [PacketFu Docs](https://github.com/packetfu/packetfu)  

**Pronto para hackear (eticamente) com Ruby!** 🔒💻
