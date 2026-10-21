/**
 * ============================================================================
 * ATIVIDADE 4 - CIFRA DE FEISTEL (16 RODADAS)
 * Disciplina: Segurança em Sistemas de Computação
 * ============================================================================
 */

// ----------------------------------------------------------------------------
// 1. TABELA S-BOX (DES S-Box 1 Oficial - Referência [2] da atividade)
// ----------------------------------------------------------------------------
// Uma S-Box (Substitution-Box) recebe 6 bits de entrada e devolve 4 bits de saída.
// Ela adiciona não-linearidade ("confusão") à função F.
const DES_SBOX_1 = [
  [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
  [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
  [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
  [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
];

// ----------------------------------------------------------------------------
// 2. FUNÇÃO F (FUNÇÃO DE RODADA / MANGLED FUNCTION)
// ----------------------------------------------------------------------------
/**
 * Aplica confusão e difusão em um meio-bloco de 32 bits.
 * Importante: Esta função NÃO precisa ser invertível, pois a reversibilidade
 * da Rede de Feistel é garantida pela operação XOR externa.
 *
 * @param {number} metadeDireita - Bloco de 32 bits (R_{i-1})
 * @param {number} subchave - Subchave de 32 bits da rodada atual (K_i)
 * @returns {number} Resultado de 32 bits após passar pela função F
 */
function funcaoF(metadeDireita, subchave) {
  // Passo A: Mistura inicial via XOR entre os dados e a subchave da rodada
  // O operador '>>> 0' no JS força o número a ser tratado como inteiro de 32 bits sem sinal (unsigned)
  let estado = (metadeDireita ^ subchave) >>> 0;

  // Passo B: Substituição via S-Box (Dividimos os 32 bits em 8 fatias de 4 bits)
  let saidaSBox = 0;
  for (let i = 0; i < 8; i++) {
    // Extrai 6 bits do estado atual para consultar a S-Box do DES
    const deslocamento = (i * 4) % 26;
    const seisBits = (estado >>> deslocamento) & 0b111111; // Máscara para isolar 6 bits (0 a 63)

    // No padrão DES: a linha (0 a 3) é formada pelo 1º e 6º bit
    const linha = ((seisBits & 0b100000) >>> 4) | (seisBits & 0b000001);
    // A coluna (0 a 15) é formada pelos 4 bits centrais
    const coluna = (seisBits >>> 1) & 0b01111;

    // Consulta o valor de 4 bits na S-Box
    const valorSubstituido = DES_SBOX_1[linha][coluna];

    // Empacota os 4 bits substituídos no resultado de 32 bits
    saidaSBox = (saidaSBox | (valorSubstituido << (i * 4))) >>> 0;
  }

  // Passo C: Difusão (Rotação circular de bits para a esquerda em 5 posições)
  const resultadoFinal = ((saidaSBox << 5) | (saidaSBox >>> (32 - 5))) >>> 0;

  return resultadoFinal;
}

// ----------------------------------------------------------------------------
// 3. ESCALONAMENTO DE CHAVES (KEY SCHEDULE)
// ----------------------------------------------------------------------------
/**
 * Gera 16 subchaves de 32 bits a partir de uma chave principal (string).
 *
 * @param {string} chaveSecreta - Chave textual informada pelo usuário
 * @param {number} numRodadas - Quantidade de rodadas (padrão = 16)
 * @returns {number[]} Array contendo as 16 subchaves (K_0 até K_15)
 */
function gerarSubchaves(chaveSecreta, numRodadas = 16) {
  // Converte a string da chave em uma semente numérica de 32 bits (Hash simples DJB2)
  let semente = 5381;
  for (let i = 0; i < chaveSecreta.length; i++) {
    semente = ((semente << 5) + semente + chaveSecreta.charCodeAt(i)) >>> 0;
  }

  const subchaves = [];
  let estadoChave = semente;

  // Deriva uma subchave diferente para cada uma das 16 rodadas
  for (let rodada = 0; rodada < numRodadas; rodada++) {
    // Mistura o estado da chave com constantes mágicas (proporção áurea: 0x9E3779B9) e rotação
    estadoChave = (estadoChave ^ (0x9e3779b9 + rodada * 0x1000193)) >>> 0;
    estadoChave = ((estadoChave << 7) | (estadoChave >>> (32 - 7))) >>> 0;
    subchaves.push(estadoChave);
  }

  return subchaves;
}

// ----------------------------------------------------------------------------
// 4. NÚCLEO DA REDE DE FEISTEL (BLOCO DE 64 BITS = L de 32 bits + R de 32 bits)
// ----------------------------------------------------------------------------
/**
 * Executa as 16 rodadas de Feistel em um único bloco de 64 bits (dividido em L e R).
 * Observe como este mesmo método serve TANTO para encriptar QUANTO para decriptar!
 *
 * @param {number} L - Metade esquerda do bloco (32 bits)
 * @param {number} R - Metade direita do bloco (32 bits)
 * @param {number[]} subchaves - Array de 16 subchaves (na ordem normal ou inversa)
 * @returns {number[]} Par [L_final, R_final] após as 16 rodadas
 */
function processarBlocoFeistel(L, R, subchaves) {
  let esquerda = L >>> 0;
  let direita = R >>> 0;

  // Executa as 16 rodadas
  for (let i = 0; i < subchaves.length; i++) {
    const esquerdaAnterior = esquerda;
    const direitaAnterior = direita;

    // Equação 1 de Feistel: L_i = R_{i-1}
    esquerda = direitaAnterior;

    // Equação 2 de Feistel: R_i = L_{i-1} XOR f(R_{i-1}, K_i)
    // O operador '^' é o XOR em JavaScript (autorreversível: A ^ B ^ B = A)
    const saidaF = funcaoF(direitaAnterior, subchaves[i]);
    direita = (esquerdaAnterior ^ saidaF) >>> 0;
  }

  // Troca final (Final Swap): após a 16ª rodada, invertemos L e R.
  // Isso garante que a decriptação seja estruturalmente idêntica à encriptação!
  return [direita, esquerda];
}

// ----------------------------------------------------------------------------
// 5. FUNÇÕES UTILITÁRIAS DE CONVERSÃO (TEXTO <-> BLOCOS DE 64 BITS)
// ----------------------------------------------------------------------------
/**
 * Converte uma string de texto (UTF-8) em um array de blocos [L, R] de 32 bits cada,
 * aplicando preenchimento (padding com zeros) para múltiplos de 8 bytes (64 bits).
 */
function textoParaBlocos(texto) {
  const encoder = new TextEncoder();
  const bytes = encoder.encode(texto);

  // Calcula tamanho múltiplo de 8 bytes (64 bits)
  const tamanhoPreenchido = Math.ceil(bytes.length / 8) * 8 || 8;
  const buffer = new Uint8Array(tamanhoPreenchido);
  buffer.set(bytes); // O restante é automaticamente preenchido com 0 (Null padding)

  const view = new DataView(buffer.buffer);
  const blocos = [];

  for (let i = 0; i < tamanhoPreenchido; i += 8) {
    const L = view.getUint32(i, false); // Primeiros 32 bits (Big-Endian)
    const R = view.getUint32(i + 4, false); // Últimos 32 bits (Big-Endian)
    blocos.push([L, R]);
  }
  return blocos;
}

/**
 * Converte um array de blocos [L, R] de volta para string ou formato Hexadecimal.
 */
function blocosParaBytes(blocos) {
  const buffer = new Uint8Array(blocos.length * 8);
  const view = new DataView(buffer.buffer);

  blocos.forEach(([L, R], index) => {
    view.setUint32(index * 8, L, false);
    view.setUint32(index * 8 + 4, R, false);
  });
  return buffer;
}

function bytesParaHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function bytesParaTexto(bytes) {
  // Remove bytes nulos de padding do final antes de decodificar para string
  let fim = bytes.length;
  while (fim > 0 && bytes[fim - 1] === 0) {
    fim--;
  }
  const decoder = new TextDecoder();
  return decoder.decode(bytes.slice(0, fim));
}

// ----------------------------------------------------------------------------
// 6. INTERFACE DE ENCRIPTAÇÃO E DECRIPTAÇÃO
// ----------------------------------------------------------------------------
function encriptar(textoPlano, chave) {
  // Na encriptação, usamos as subchaves na ordem original: K_0, K_1, ..., K_15
  const subchaves = gerarSubchaves(chave, 16);
  const blocosEntrada = textoParaBlocos(textoPlano);

  const blocosCifrados = blocosEntrada.map(([L, R]) =>
    processarBlocoFeistel(L, R, subchaves)
  );

  return {
    blocos: blocosCifrados,
    hex: bytesParaHex(blocosParaBytes(blocosCifrados)),
  };
}

function decriptar(blocosCifrados, chave) {
  // Na decriptação, usamos EXATAMENTE O MESMO ALGORITMO,
  // apenas invertendo a ordem das subchaves: K_15, K_14, ..., K_0
  const subchavesInvertidas = gerarSubchaves(chave, 16).reverse();

  const blocosDecifrados = blocosCifrados.map(([L, R]) =>
    processarBlocoFeistel(L, R, subchavesInvertidas)
  );

  const bytesRecuperados = blocosParaBytes(blocosDecifrados);
  return bytesParaTexto(bytesRecuperados);
}

// ============================================================================
// 7. DEMONSTRAÇÃO E TESTE PRÁTICO
// ============================================================================
const mensagemOriginal =
  "Seguranca em Sistemas de Computacao - Feistel 16 Rodadas!";
const minhaChave = "ChaveSuperSecreta2026";

console.log("=== DEMONSTRAÇÃO: CIFRA DE FEISTEL (16 RODADAS) ===");
console.log("1. Texto Original:   ", mensagemOriginal);
console.log("2. Chave Utilizada:  ", minhaChave);

// Encriptando
const resultadoCifrado = encriptar(mensagemOriginal, minhaChave);
console.log("3. Texto Cifrado (Hex):", resultadoCifrado.hex);

// Decriptando
const textoRecuperado = decriptar(resultadoCifrado.blocos, minhaChave);
console.log("4. Texto Decriptado: ", textoRecuperado);
console.log(
  "5. Sucesso na reversão?",
  mensagemOriginal === textoRecuperado ? "SIM ✅" : "NÃO ❌"
);
