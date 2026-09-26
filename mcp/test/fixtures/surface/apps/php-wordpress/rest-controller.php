<?php
/**
 * Controlador REST do plugin — regista as rotas públicas.
 *
 * O comentário acentuado acima é intencional: os offsets do Semgrep são em
 * bytes, e uma recuperação que fatiasse por caracteres devolveria outro span.
 */

namespace Guardian\Fixture;

class Rest_Controller {

	// Not `const NAMESPACE`, the spelling many real plugins use: it is legal
	// PHP 7+ (semi-reserved words are allowed as class-constant names), but
	// Semgrep's PHP parser cannot read it — 1.164.0 and 1.176.1 emit a
	// `PartialParsing` warning naming these lines (1.86.0 parsed it cleanly).
	// map_attack_surface treats any Semgrep `errors[]` entry as a failed run
	// and persists nothing (Global Constraint 3), so that spelling here would
	// make every real-Semgrep test of this fixture a test of the failure path.
	// A project that uses it gets `semgrep: failed` naming the file.
	const REST_NAMESPACE = 'guardian/v2';

	public function register(): void {
		// Literal namespace: resolvable to /wp-json/guardian/v1/items.
		register_rest_route(
			'guardian/v1',
			'/items',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'get_items' ),
				'permission_callback' => '__return_true',
			)
		);

		// Computed namespace — the dominant idiom in real plugins. There is no
		// honest way to name the served URL, so the route must be reported as
		// partial rather than as /wp-json/self::REST_NAMESPACE/items.
		register_rest_route(
			self::REST_NAMESPACE,
			'/items/(?P<id>\d+)',
			array(
				'methods'  => 'DELETE',
				'callback' => array( $this, 'delete_item' ),
			)
		);
	}

	public function get_items() {
		$key = getenv( 'WP_API_KEY' );
		return rest_ensure_response( array( 'has_key' => (bool) $key ) );
	}

	public function delete_item( $request ) {
		return rest_ensure_response( array( 'deleted' => $request['id'] ) );
	}
}
