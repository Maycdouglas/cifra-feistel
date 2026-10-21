# cifra-feistel

Atividade sobre Cifra de Feistel desenvolvida na disciplina Segurança em Sistemas de Informação.

## Requisitos

- Node.js instalado no sistema

## Executando o projeto

1. Abra o terminal na raiz do projeto:

   ```bash
   cd c:\caminho\para\cifra-feistel
   ```

2. Execute o script principal:

   ```bash
   node main.js
   ```

3. O programa irá:
   - gerar uma chave fixa;
   - cifrar uma mensagem com a estrutura Feistel;
   - decifrar o bloco cifrado;
   - imprimir o resultado final no terminal.

## Resultado esperado

Ao final da execução, a saída deve indicar que a reversão foi bem-sucedida:

```bash
5. Sucesso na reversão? SIM ✅
```

## Como foi implementado

Código gerado com o `Gemini AI`, da Google. O modelo utilizado foi o `Argon` com nível de raciocínio no máximo.

Prompt usado:

```
"Você é um especialista em Segurança em Sistemas de Computação. Você me ajudará com atividades práticas da disciplina na universidade. Preciso que me explique didaticamente o que cada atividade pede e depois implemente o que é pedido em JAVA SCRIPT.

Atividade 4 - Cifra de Feistel

Envie um código implementando uma Cifra de Feistel com 16 rodadas.

Coloque comentários no seu código

Esperamos que seja feita a Encriptação e Decriptação.

Para decriptar, as operações matemáticas utilizadas na encriptação devem permitir reversão. Por exemplo (e.g. - exempli gratia), XOR é autorreversível.

Não se preocupe tanto com a função "f", apesar de ser obrigatória para uma proposta forte criptograficamente, este exercício visa permitir a compreensão do conceito.

Portanto, na sua proposta da função "f" pode-se realizar operações simples (como o XOR ou outra mesmo linear), ou se avançar no desafio, usar as caixas S-BOX, mas sem a premissa de construção de S-BOX fortes (como descrito em [1]), podendo utilizar as S-BOX do DES [2] ou de outro algoritmo.

[1] https://www.nature.com/articles/s41598-023-47607-6

[2] https://en.wikipedia.org/wiki/DES_supplementary_material"
```
