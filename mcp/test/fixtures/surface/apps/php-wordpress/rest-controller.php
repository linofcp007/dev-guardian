<?php
/**
 * Controlador REST do plugin — regista as rotas públicas.
 *
 * O comentário acentuado acima é intencional: os offsets do Semgrep são em
 * bytes, e uma recuperação que fatiasse por caracteres devolveria outro span.
 */

namespace Guardian\Fixture;

class Rest_Controller {

	// `const NAMESPACE` is legal PHP 7+ (semi-reserved words are allowed as
	// class-constant names) and common in real plugins, but Semgrep's PHP
	// parser cannot read it: every run over this file emits a `PartialParsing`
	// *warning* naming these lines. That is expected, and deliberately left in
	// — both register_rest_route() calls below still match, which is the point
	// worth pinning. Renaming the constant makes the warning disappear.
	const NAMESPACE = 'guardian/v2';

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
		// partial rather than as /wp-json/self::NAMESPACE/items.
		register_rest_route(
			self::NAMESPACE,
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
