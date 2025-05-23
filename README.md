# Aulão de Ruby v1
---

**Introdução à Sintaxe Ruby**  

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

### **1. Configuração **  
- Instalação do Ruby (Linux/Windows/Mac)  
- Uso do IRB (Interactive Ruby Shell)  
- Primeiro programa:  
  ```ruby
  puts "Olá, mundo!"  
  ```

### **2. Fundamentos **  
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

### **3. Exercício Prático **  
**Calculadora Simples**:  
```ruby
puts "Digite um número:"  
num1 = gets.to_f  
puts "Digite outro número:"  
num2 = gets.to_f  
puts "Soma: #{num1 + num2}"  
```

---

Estruturas de Controle e Coleções**  
**Objetivo:** Dominar condicionais e loops  

### **1. Condicionais**  
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

### **2. Arrays e Hashes**  
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

### **3. Loops**  
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

### **2. Classes**  
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
