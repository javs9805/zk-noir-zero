//! Verificador de Firmas Digitales BLS12-381
//! 
//! Este módulo implementa un verificador completo de firmas digitales basado en
//! el esquema BLS sobre la curva elíptica BLS12-381.
//!
//! ## Esquema BLS
//! 
//! La verificación de firma BLS se basa en emparejamientos bilineales:
//! 
//! ```text
//! Verificación: e(σ, G₂) == e(H(m), pk)
//! 
//! Donde:
//! - σ: firma (punto en G₂)
//! - G₂: generador del grupo G₂
//! - H(m): hash del mensaje mapeado a G₁ (Hash-to-Curve)
//! - pk: clave pública (punto en G₁)
//! - e: función de emparejamiento bilineal
//! ```
//!
//! ## Estándares cumplidos
//! 
//! - IETF Hash-to-Curve (draft-irtf-cfrg-hash-to-curve)
//! - BLS Signature Scheme (draft-irtf-cfrg-bls-signature)
//! - Domain Separation Tag (DST) para prevenir ataques de dominio cruzado

use std::{fs, env};
use bls12_381_plus::{G1Affine, G2Affine, G1Projective, G2Projective, Gt};
use bls12_381_plus::elliptic_curve::hash2curve::ExpandMsgXmd;
use bls12_381_plus::group::Group;
use sha2::{Sha256, Digest};
use serde::{Deserialize, Serialize};

// ============================================================================
// CONSTANTES CRIPTOGRÁFICAS
// ============================================================================

/// Domain Separation Tag (DST) según estándar IETF para BLS12-381
/// Corresponde al DST usado por Ethereum para la capa de consenso (beacon chain)
const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// Longitud esperada de clave pública G1 comprimida (bytes)
const G1_COMPRESSED_SIZE: usize = 48;

/// Longitud esperada de firma G2 comprimida (bytes)
const G2_COMPRESSED_SIZE: usize = 96;

/// DOMAIN_SYNC_COMMITTEE según la spec de Ethereum (0x07000000)
const DOMAIN_SYNC_COMMITTEE: [u8; 4] = [0x07, 0x00, 0x00, 0x00];

// ============================================================================
// ESTRUCTURAS DE DATOS
// ============================================================================

#[derive(Deserialize)]
struct SyncCommittee {
	pubkeys: Vec<String>,
	#[serde(default)]
	aggregate_pubkey: Option<String>,
}

#[derive(Deserialize)]
struct BlockData {
	/// Root del bloque beacon firmado (mensaje)
	#[serde(default)]
	beacon_block_root: Option<String>,
	/// Parent root: el bloque que realmente fue firmado por el sync committee
	#[serde(default, rename = "parentRoot")]
	parent_root: Option<String>,
	/// Firma agregada del sync committee (G2)
	#[serde(default)]
	sync_aggregate_signature: Option<String>,
	/// Número de slot del bloque
	#[serde(default)]
	slot: Option<u64>,
}

#[derive(Deserialize)]
struct SyncAggregateData {
	#[serde(default)]
	sync_committee_signature: Option<String>,
}

#[derive(Deserialize)]
struct BlockHeaderData {
	#[serde(default)]
	slot: Option<String>,
	#[serde(default)]
	sync_aggregate: Option<SyncAggregateData>,
}

#[derive(Deserialize)]
struct Root {
	#[serde(default, rename = "blockRoot")]
	block_root: Option<String>,
	#[serde(default, rename = "blockHeader")]
	block_header: Option<BlockHeaderData>,
	#[serde(default, rename = "syncCommittee")]
	sync_committee: Option<SyncCommittee>,
	#[serde(default, rename = "validPublicKeys")]
	valid_public_keys: Option<Vec<String>>,
	#[serde(default, rename = "blockData")]
	block_data: Option<BlockData>,
	#[serde(default)]
	genesis: Option<GenesisInfo>,
	#[serde(default)]
	fork: Option<ForkInfo>,
	#[serde(default)]
	participation: Option<ParticipationInfo>,
}

#[derive(Deserialize)]
struct GenesisInfo {
	#[serde(default, rename = "genesisValidatorsRoot")]
	genesis_validators_root: Option<String>,
	#[allow(dead_code)]
	#[serde(default, rename = "genesisForkVersion")]
	genesis_fork_version: Option<String>,
}

#[derive(Deserialize)]
struct ForkInfo {
	#[serde(default, rename = "currentVersion")]
	current_version: Option<String>,
}

#[derive(Deserialize)]
struct ParticipationInfo {
	#[serde(default, rename = "bitsArray")]
	bits_array: Option<Vec<u8>>,
}

#[derive(Serialize)]
struct KeyValidity {
	key: String,
	valid: bool,
	#[serde(skip_serializing_if = "Option::is_none")]
	message: Option<String>,
}

#[derive(Serialize)]
struct SignatureVerification {
	message: String,
	signature: String,
	public_key: String,
	valid: bool,
	#[serde(skip_serializing_if = "Option::is_none")]
	slot: Option<u64>,
}

#[derive(Serialize)]
struct Output {
	#[serde(rename = "syncCommitteeResults")]
	sync_committee_results: Vec<KeyValidity>,
	#[serde(rename = "aggregatePubkeyValid")]
	aggregate_pubkey_valid: Option<bool>,
	#[serde(rename = "validPublicKeysResults")]
	valid_public_keys_results: Vec<KeyValidity>,
	#[serde(rename = "signatureVerification")]
	signature_verification: Option<SignatureVerification>,
}

// ============================================================================
// FUNCIONES AUXILIARES CRIPTOGRÁFICAS
// ============================================================================

/// Decodifica una cadena hexadecimal con prefijo opcional "0x"
///
/// # Argumentos
/// * `hex_str` - Cadena hexadecimal a decodificar
///
/// # Retorna
/// * `Result<Vec<u8>, hex::FromHexError>` - Bytes decodificados o error
fn decode_hex(hex_str: &str) -> Result<Vec<u8>, hex::FromHexError> {
	let clean = hex_str.strip_prefix("0x").unwrap_or(hex_str);
	hex::decode(clean)
}

/// Valida que una clave pública G1 en formato hexadecimal sea válida
///
/// # Seguridad
/// - Verifica longitud correcta (48 bytes comprimidos)
/// - Valida que el punto esté en la curva
/// - Rechaza el punto identidad (infinito) como clave pública
///
/// # Argumentos
/// * `hex_pubkey` - Clave pública en formato hexadecimal
///
/// # Retorna
/// * `bool` - true si la clave es válida, false en caso contrario
fn is_valid_g1_pubkey_hex(hex_pubkey: &str) -> bool {
	let bytes = match decode_hex(hex_pubkey) {
		Ok(b) => b,
		Err(_) => return false,
	};

	// Validar longitud
	if bytes.len() != G1_COMPRESSED_SIZE {
		return false;
	}

	let mut arr = [0u8; G1_COMPRESSED_SIZE];
	arr.copy_from_slice(&bytes);

	// Intentar descomprimir el punto
	let point_option = G1Affine::from_compressed(&arr);
	
	if bool::from(point_option.is_some()) {
		let point = point_option.unwrap();
		// Rechazar el punto identidad (infinito) como clave pública
		// Una clave pública válida debe ser un punto no trivial en G1
		!bool::from(point.is_identity())
	} else {
		false
	}
}

/// Agrega múltiples claves públicas en una sola clave pública agregada
///
/// Esta función implementa la agregación de claves públicas BLS sumando
/// los puntos de la curva elíptica G₁. Es fundamental para verificar
/// firmas agregadas del Sync Committee.
///
/// # Algoritmo
/// ```text
/// PK_agg = PK₁ + PK₂ + PK₃ + ... + PKₙ
/// ```
///
/// # Argumentos
/// * `pubkeys` - Vector de claves públicas en formato hexadecimal
///
/// # Retorna
/// * `Ok(G1Affine)` - Clave pública agregada
/// * `Err(String)` - Error si alguna clave es inválida
///
/// # Ejemplo
/// ```rust,no_run
/// let pubkeys = vec!["0xabc...", "0xdef..."];
/// let aggregate = aggregate_public_keys(&pubkeys)?;
/// ```
pub fn aggregate_public_keys(pubkeys: &[String]) -> Result<G1Affine, String> {
	let mut aggregate = G1Projective::identity(); // Punto identidad (neutral para suma)
	
	for pubkey_hex in pubkeys {
		// Decodificar clave pública desde hex
		let pubkey_bytes = decode_hex(pubkey_hex)
			.map_err(|e| format!("Error decodificando hex: {}", e))?;
		
		if pubkey_bytes.len() != G1_COMPRESSED_SIZE {
			return Err(format!("Longitud incorrecta: {} bytes (esperado {})", 
							 pubkey_bytes.len(), G1_COMPRESSED_SIZE));
		}
		
		let mut pk_array = [0u8; G1_COMPRESSED_SIZE];
		pk_array.copy_from_slice(&pubkey_bytes);
		
		// Deserializar punto G1
		let pk_affine = G1Affine::from_compressed(&pk_array)
			.into_option()
			
			.ok_or("Punto no válido en la curva G₁")?;
		// Sumar a la agregación
		aggregate += G1Projective::from(pk_affine);
	}
	
	Ok(G1Affine::from(aggregate))
}

/// Implementa Hash-to-Curve conforme al estándar IETF RFC 9380
///
/// Mapea un mensaje arbitrario a un punto en el grupo G₂ de BLS12-381
/// usando el pipeline completo:
///
/// ```text
/// message → expand_message_xmd(SHA-256) → hash_to_field → map_to_curve(SSWU) → clear_cofactor → G₂
/// ```
///
/// Esta implementación es compatible con Ethereum beacon chain y cumple
/// con el estándar IETF (draft-irtf-cfrg-hash-to-curve).
///
/// # Argumentos
/// * `message` - Mensaje a mapear a la curva
///
/// # Retorna
/// * `G2Projective` - Punto en G₂ uniformemente distribuido
fn hash_to_curve_g2(message: &[u8]) -> G2Projective {
	G2Projective::hash::<ExpandMsgXmd<Sha256>>(message, DST)
}

// ============================================================================
// FUNCIONES DE DOMINIO ETHEREUM (Signing Root)
// ============================================================================

/// Computa el dominio Ethereum para verificación de firmas BLS.
///
/// Implementa compute_domain según la spec de Ethereum:
/// 1. fork_data_root = hash_tree_root(ForkData{fork_version, genesis_validators_root})
/// 2. domain = domain_type + fork_data_root[0..28]
fn compute_domain(
	domain_type: &[u8; 4],
	fork_version: &[u8; 4],
	genesis_validators_root: &[u8; 32],
) -> [u8; 32] {
	// ForkData SSZ hash_tree_root:
	// hash(fork_version_padded_to_32 || genesis_validators_root)
	let mut fork_version_padded = [0u8; 32];
	fork_version_padded[..4].copy_from_slice(fork_version);

	let mut hasher = Sha256::new();
	hasher.update(fork_version_padded);
	hasher.update(genesis_validators_root);
	let fork_data_root: [u8; 32] = hasher.finalize().into();

	// domain = domain_type (4 bytes) + fork_data_root[0..28]
	let mut domain = [0u8; 32];
	domain[..4].copy_from_slice(domain_type);
	domain[4..].copy_from_slice(&fork_data_root[..28]);
	domain
}

/// Computa el signing_root según la spec de Ethereum.
///
/// signing_root = hash_tree_root(SigningData{object_root, domain})
/// SigningData SSZ = hash(object_root || domain)
fn compute_signing_root(object_root: &[u8; 32], domain: &[u8; 32]) -> [u8; 32] {
	let mut hasher = Sha256::new();
	hasher.update(object_root);
	hasher.update(domain);
	hasher.finalize().into()
}

/// Agrega solo las claves públicas de los validadores que participaron,
/// según el bitfield sync_committee_bits.
fn aggregate_participating_keys(
	pubkeys: &[String],
	bits: &[u8],
) -> Result<(G1Affine, usize), String> {
	let mut aggregate = G1Projective::identity();
	let mut count = 0usize;

	for (i, pubkey_hex) in pubkeys.iter().enumerate() {
		let participated = bits.get(i).copied().unwrap_or(0) == 1;
		if !participated {
			continue;
		}

		let pubkey_bytes = decode_hex(pubkey_hex)
			.map_err(|e| format!("Error decodificando hex en índice {}: {}", i, e))?;

		if pubkey_bytes.len() != G1_COMPRESSED_SIZE {
			return Err(format!("Clave {} longitud incorrecta: {}", i, pubkey_bytes.len()));
		}

		let mut pk_array = [0u8; G1_COMPRESSED_SIZE];
		pk_array.copy_from_slice(&pubkey_bytes);

		let pk_affine = G1Affine::from_compressed(&pk_array)
			.into_option()
			.ok_or(format!("Clave {} no es un punto válido en G₁", i))?;

		aggregate += G1Projective::from(pk_affine);
		count += 1;
	}

	Ok((G1Affine::from(aggregate), count))
}

/// Calcula el emparejamiento bilineal e: G₁ × G₂ → Gₜ
///
/// # Argumentos
/// * `g1_point` - Punto en G₁
/// * `g2_point` - Punto en G₂
///
/// # Retorna
/// * `Gt` - Elemento en el grupo objetivo Gₜ
fn pairing(g1_point: &G1Affine, g2_point: &G2Affine) -> Gt {
	bls12_381_plus::pairing(g1_point, g2_point)
}

// ============================================================================
// FUNCIÓN PRINCIPAL DE VERIFICACIÓN BLS
// ============================================================================

/// Verifica una firma BLS12-381 usando emparejamientos bilineales
///
/// # Esquema de verificación
///
/// ```text
/// Verificación exitosa si y solo si:
/// e(pk, H(m)) == e(G₁, σ)
/// 
/// Equivalentemente (ecuación utilizada aquí):
/// e(G₁, σ) == e(pk, H(m))
/// 
/// Donde:
/// - pk: clave pública (punto en G₁)
/// - H(m): hash del mensaje a G₂ (Hash-to-Curve)
/// - σ: firma (punto en G₂)
/// - G₁: generador del grupo G₁
/// - e: función de emparejamiento bilineal
/// ```
///
/// # Argumentos
///
/// * `message` - Mensaje original firmado (byte array)
/// * `signature` - Firma BLS (punto G₂ serializado, 96 bytes)
/// * `public_key` - Clave pública BLS (punto G₁ serializado, 48 bytes)
///
/// # Retorna
///
/// * `Result<bool, String>` - Ok(true) si la firma es válida, Ok(false) si no,
///   Err si hay error en el formato de datos
///
/// # Seguridad
///
/// - Valida longitudes de entrada según estándar BLS12-381
/// - Verifica que los puntos estén en la curva
/// - Usa DST para prevenir ataques de dominio cruzado
/// - Implementa verificación de ecuación de emparejamiento
///
/// # Ejemplo
///
/// ```rust,no_run
/// let message = b"Hello, BLS!";
/// let signature = &[0u8; 96]; // firma de ejemplo
/// let public_key = &[0u8; 48]; // clave pública de ejemplo
///
/// match verify_bls_signature(message, signature, public_key) {
///     Ok(true) => println!("✓ Firma válida"),
///     Ok(false) => println!("✗ Firma inválida"),
///     Err(e) => eprintln!("Error: {}", e),
/// }
/// ```
fn verify_bls_signature(
	message: &[u8],
	signature: &[u8],
	public_key: &[u8]
) -> Result<bool, String> {
	// ========================================================================
	// 1. VALIDACIÓN Y DESERIALIZACIÓN DE CLAVE PÚBLICA (G₁)
	// ========================================================================
	
	if public_key.len() != G1_COMPRESSED_SIZE {
		return Err(format!(
			"Longitud de clave pública inválida: esperado {} bytes, recibido {}",
			G1_COMPRESSED_SIZE, public_key.len()
		));
	}

	let mut pk_array = [0u8; G1_COMPRESSED_SIZE];
	pk_array.copy_from_slice(public_key);

	let pk_affine = G1Affine::from_compressed(&pk_array)
		.into_option()
		.ok_or_else(|| "Clave pública no es un punto válido en G₁".to_string())?;

	// Verificar que no sea el punto identidad
	if bool::from(pk_affine.is_identity()) {
		return Err("Clave pública no puede ser el punto identidad".to_string());
	}

	// ========================================================================
	// 2. VALIDACIÓN Y DESERIALIZACIÓN DE FIRMA (G₂)
	// ========================================================================
	
	if signature.len() != G2_COMPRESSED_SIZE {
		return Err(format!(
			"Longitud de firma inválida: esperado {} bytes, recibido {}",
			G2_COMPRESSED_SIZE, signature.len()
		));
	}

	let mut sig_array = [0u8; G2_COMPRESSED_SIZE];
	sig_array.copy_from_slice(signature);

	let sig_affine = G2Affine::from_compressed(&sig_array)
		.into_option()
		.ok_or_else(|| "Firma no es un punto válido en G₂".to_string())?;

	// ========================================================================
	// 3. HASH-TO-CURVE DEL MENSAJE
	// ========================================================================
	
	// Mapear el mensaje a un punto en G₂ usando Hash-to-Curve
	let message_hash_g2 = hash_to_curve_g2(message);
	let message_hash_affine = G2Affine::from(message_hash_g2);

	// ========================================================================
	// 4. VERIFICACIÓN DE EMPAREJAMIENTO BILINEAL
	// ========================================================================
	
	// Obtener el generador de G₁
	let g1_generator = G1Affine::generator();

	// Calcular emparejamientos:
	// left  = e(G₁, σ)
	// right = e(pk, H(m))
	let left = pairing(&g1_generator, &sig_affine);
	let right = pairing(&pk_affine, &message_hash_affine);

	// La firma es válida si y solo si los emparejamientos son iguales
	Ok(left == right)
}

// ============================================================================
// FUNCIÓN PRINCIPAL
// ============================================================================

/// Extrae el parent_root (el bloque que realmente firmó el sync committee).
/// El sync_aggregate en el slot N firma el block root del slot N-1 (parent_root).
fn extract_signed_block_root(root: &Root) -> Option<String> {
	// Preferir parent_root si está disponible
	root.block_data
		.as_ref()
		.and_then(|bd| bd.parent_root.clone())
		.or_else(|| {
			// Fallback al beacon_block_root si no hay parent_root
			root.block_data
				.as_ref()
				.and_then(|bd| bd.beacon_block_root.clone())
				.or_else(|| root.block_root.clone())
		})
}

fn extract_slot(root: &Root) -> Option<u64> {
	root.block_data
		.as_ref()
		.and_then(|bd| bd.slot)
		.or_else(|| {
			root.block_header
				.as_ref()
				.and_then(|bh| bh.slot.as_ref())
				.and_then(|slot| slot.parse::<u64>().ok())
		})
}

fn extract_sync_signature(root: &Root) -> Option<String> {
	root.block_data
		.as_ref()
		.and_then(|bd| bd.sync_aggregate_signature.clone())
		.or_else(|| {
			root.block_header
				.as_ref()
				.and_then(|bh| bh.sync_aggregate.as_ref())
				.and_then(|sa| sa.sync_committee_signature.clone())
		})
}

/// Valida y agrega claves G1 en una sola pasada, evitando deserializar cada
/// punto dos veces (una para validar y otra para agregar).
fn validate_and_aggregate_keys(
	pubkeys: &[String],
	message: &Option<String>,
) -> (Vec<KeyValidity>, Option<G1Affine>) {
	let mut results = Vec::with_capacity(pubkeys.len());
	let mut aggregate = G1Projective::identity();
	let mut any_valid = false;

	for (i, key) in pubkeys.iter().enumerate() {
		let maybe_point: Option<G1Affine> = (|| {
			let bytes = decode_hex(key).ok()?;
			if bytes.len() != G1_COMPRESSED_SIZE { return None; }
			let mut arr = [0u8; G1_COMPRESSED_SIZE];
			arr.copy_from_slice(&bytes);
			let point = G1Affine::from_compressed(&arr).into_option()?;
			if bool::from(point.is_identity()) { return None; }
			Some(point)
		})();

		let valid = maybe_point.is_some();
		if !valid {
			println!("  ✗ Clave {} inválida", i + 1);
		}
		if let Some(point) = maybe_point {
			aggregate += G1Projective::from(point);
			any_valid = true;
		}
		results.push(KeyValidity { key: key.clone(), valid, message: message.clone() });
	}

	let agg = if any_valid { Some(G1Affine::from(aggregate)) } else { None };
	(results, agg)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
	// Leer ruta de JSON y salida
	let args: Vec<String> = env::args().collect();
	
	// Mostrar ayuda si se solicita
	if args.len() > 1 && (args[1] == "--help" || args[1] == "-h") {
		println!("═══════════════════════════════════════════════════════════");
		println!("  Verificador de Firmas BLS12-381");
		println!("  Modo Offline: validación desde JSON local");
		println!("  Esquema: BLS Signature con Hash-to-Curve (IETF)");
		println!("═══════════════════════════════════════════════════════════\n");
		println!("Uso: {} [INPUT_JSON] [OUTPUT_JSON]", args[0]);
		println!("\nArgumentos:");
		println!("  INPUT_JSON    Archivo con datos del Sync Committee (opcional)");
		println!("                Por defecto: data.json");
		println!("  OUTPUT_JSON   Archivo de resultados (opcional)");
		println!("                Por defecto: validation_results.json");
		println!("\nEjemplos:");
		println!("  {}", args[0]);
		println!("  {} data.json", args[0]);
		println!("  {} data.json validation_results.json", args[0]);
		return Ok(());
	}
	
	let input_json = if args.len() > 1 {
		args[1].clone()
	} else {
		"data.json".to_string()
	};

	let output_json = if args.len() > 2 {
		args[2].clone()
	} else {
		"validation_results.json".to_string()
	};
	
	println!("═══════════════════════════════════════════════════════════");
	println!("  Verificador de Firmas BLS12-381");
	println!("  Modo Offline: validación desde JSON local");
	println!("  Esquema: BLS Signature con Hash-to-Curve (IETF)");
	println!("  Input JSON: {}", input_json);
	println!("  Output JSON: {}", output_json);
	println!("═══════════════════════════════════════════════════════════\n");

	let json_content = fs::read_to_string(&input_json)?;
	let root: Root = serde_json::from_str(&json_content)?;
	println!("✓ JSON cargado correctamente\n");

	// ========================================================================
	// VALIDACIÓN DE CLAVES PÚBLICAS DEL SYNC COMMITTEE
	// ========================================================================
	
	let mut sync_results = Vec::new();
	let mut agg_valid: Option<bool> = None;
	let message = extract_signed_block_root(&root);
	let slot = extract_slot(&root);

	// Extraer bits de participación
	let participation_bits: Option<Vec<u8>> = root.participation
		.as_ref()
		.and_then(|p| p.bits_array.clone());

	if let Some(sc) = &root.sync_committee {
		println!("📋 Validando {} claves públicas del Sync Committee...", sc.pubkeys.len());

		let (results, computed_agg) = validate_and_aggregate_keys(&sc.pubkeys, &message);
		let valid_count = results.iter().filter(|k| k.valid).count();
		println!("  ✓ Válidas: {}/{}\n", valid_count, results.len());
		sync_results = results;

		// Usar aggregate_pubkey del JSON si existe, si no usar el calculado en el paso anterior
		let agg_point = if let Some(existing_hex) = &sc.aggregate_pubkey {
			decode_hex(existing_hex).ok()
				.filter(|b| b.len() == G1_COMPRESSED_SIZE)
				.and_then(|b| {
					let mut arr = [0u8; G1_COMPRESSED_SIZE];
					arr.copy_from_slice(&b);
					G1Affine::from_compressed(&arr).into_option()
						.filter(|p| !bool::from(p.is_identity()))
				})
		} else {
			computed_agg
		};

		agg_valid = Some(agg_point.is_some());
		println!("🔑 Clave pública agregada: {}\n",
			if agg_valid.unwrap() { "✓ Válida" } else { "✗ Inválida" });
	}

	// ========================================================================
	// VALIDACIÓN DE CLAVES PÚBLICAS ADICIONALES
	// ========================================================================
	
	let mut valid_results = Vec::new();
	if let Some(keys) = &root.valid_public_keys {
		println!("📋 Validando {} claves públicas adicionales...", keys.len());
		
		for key in keys {
			valid_results.push(KeyValidity {
				key: key.clone(),
				valid: is_valid_g1_pubkey_hex(key),
				message: message.clone(),
			});
		}
		
		let valid_count = valid_results.iter().filter(|k| k.valid).count();
		println!("  ✓ Válidas: {}/{}\n", valid_count, valid_results.len());
	}

	// ========================================================================
	// VERIFICACIÓN DE FIRMA BLS
	// ========================================================================
	
	let mut signature_verification: Option<SignatureVerification> = None;
	let sync_signature = extract_sync_signature(&root);

	if let Some(sc) = &root.sync_committee
		&& let (Some(msg_hex), Some(sig_hex)) = (
			message.clone(),
			sync_signature
		) {
			println!("═══════════════════════════════════════════════════════════");
			println!("  🔐 VERIFICACIÓN DE FIRMA BLS (Ethereum Beacon Chain)");
			println!("═══════════════════════════════════════════════════════════");
			
			if let Some(slot) = slot {
				println!("Slot del bloque: {}", slot);
			}
			println!("Mensaje (parent_root firmado): {}", 
				if msg_hex.len() > 20 { format!("{}...{}", &msg_hex[..10], &msg_hex[msg_hex.len()-10..]) }
				else { msg_hex.clone() }
			);
			println!("Firma (sync_aggregate): {}", 
				if sig_hex.len() > 20 { format!("{}...{}", &sig_hex[..10], &sig_hex[sig_hex.len()-10..]) }
				else { sig_hex.clone() }
			);

			// ============================================================
			// Agregar solo las claves de los validadores que participaron
			// ============================================================
			let (agg_pk_affine, participant_count) = if let Some(bits) = &participation_bits {
				println!("\n🔑 Agregando claves de participantes ({}/{} validadores)...", 
					bits.iter().filter(|&&b| b == 1).count(), sc.pubkeys.len());
				aggregate_participating_keys(&sc.pubkeys, bits)
					.map_err(|e| -> Box<dyn std::error::Error> { e.into() })?
			} else {
				println!("\n⚠️  Sin bits de participación, agregando todas las {} claves...", sc.pubkeys.len());
				let agg = aggregate_public_keys(&sc.pubkeys)
					.map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
				(agg, sc.pubkeys.len())
			};

			let agg_pk_hex = format!("0x{}", hex::encode(agg_pk_affine.to_compressed()));
			println!("Clave pública agregada ({} participantes): {}", 
				participant_count,
				if agg_pk_hex.len() > 20 { format!("{}...{}", &agg_pk_hex[..10], &agg_pk_hex[agg_pk_hex.len()-10..]) }
				else { agg_pk_hex.clone() }
			);

			// ============================================================
			// Computar signing_root según la spec de Ethereum
			// ============================================================
			let message_bytes = decode_hex(&msg_hex)?;
			let signature_bytes = decode_hex(&sig_hex)?;

			let signing_message = if let (Some(genesis), Some(fork)) = (&root.genesis, &root.fork) {
				if let (Some(gvr_hex), Some(fv_hex)) = (&genesis.genesis_validators_root, &fork.current_version) {
					let gvr_bytes = decode_hex(gvr_hex)?;
					let fv_bytes = decode_hex(fv_hex)?;

					if gvr_bytes.len() == 32 && fv_bytes.len() == 4 {
						let mut gvr = [0u8; 32];
						gvr.copy_from_slice(&gvr_bytes);
						let mut fv = [0u8; 4];
						fv.copy_from_slice(&fv_bytes);

						let domain = compute_domain(&DOMAIN_SYNC_COMMITTEE, &fv, &gvr);

						let mut object_root = [0u8; 32];
						if message_bytes.len() == 32 {
							object_root.copy_from_slice(&message_bytes);
						} else {
							return Err(format!("block root debe ser 32 bytes, recibido {}", message_bytes.len()).into());
						}

						let signing_root = compute_signing_root(&object_root, &domain);

						println!("\n📐 Ethereum Signing Domain:");
						println!("  Fork version: {}", fv_hex);
						println!("  Genesis validators root: {}...{}", &gvr_hex[..10], &gvr_hex[gvr_hex.len()-10..]);
						println!("  Domain: 0x{}", hex::encode(domain));
						println!("  Signing root: 0x{}", hex::encode(signing_root));

						signing_root.to_vec()
					} else {
						println!("\n⚠️  Genesis/fork data con longitud incorrecta, usando block root directo");
						message_bytes.clone()
					}
				} else {
					println!("\n⚠️  Faltan genesis_validators_root o fork_version, usando block root directo");
					message_bytes.clone()
				}
			} else {
				println!("\n⚠️  Sin datos de genesis/fork, usando block root directo");
				message_bytes.clone()
			};

			let pubkey_bytes = agg_pk_affine.to_compressed().to_vec();

			println!("\nEjecutando verificación de emparejamiento bilineal...");
			println!("  e(G₁, σ) == e(pk_agg, H(signing_root))");
			println!();

			let verification_result = verify_bls_signature(
				&signing_message,
				&signature_bytes,
				&pubkey_bytes
			);

			let is_valid = match verification_result {
				Ok(valid) => {
					if valid {
						println!("╔═══════════════════════════════════════════════╗");
						println!("║   ✅ FIRMA VÁLIDA - VERIFICACIÓN EXITOSA      ║");
						println!("╚═══════════════════════════════════════════════╝");
					} else {
						println!("╔═══════════════════════════════════════════════╗");
						println!("║   ❌ FIRMA INVÁLIDA - VERIFICACIÓN FALLIDA    ║");
						println!("╚═══════════════════════════════════════════════╝");
					}
					valid
				},
				Err(e) => {
					println!("⚠️  Error en verificación: {}", e);
					false
				}
			};

			signature_verification = Some(SignatureVerification {
				message: msg_hex.clone(),
				signature: sig_hex.clone(),
				public_key: agg_pk_hex,
				valid: is_valid,
				slot,
			});

			println!("═══════════════════════════════════════════════════════════\n");
		}

	// ========================================================================
	// GENERAR ARCHIVO DE RESULTADOS
	// ========================================================================
	
	let output = Output {
		sync_committee_results: sync_results,
		aggregate_pubkey_valid: agg_valid,
		valid_public_keys_results: valid_results,
		signature_verification,
	};

	let out_str = serde_json::to_string_pretty(&output)?;
	fs::write(&output_json, out_str)?;

	println!("📄 Resultados guardados en: {}", output_json);
	println!("✓ Ejecución completada exitosamente.\n");

	Ok(())
}
