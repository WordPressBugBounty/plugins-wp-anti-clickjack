<?php
/**
 * Plugin Name: WP Anti-Clickjack
 * Plugin URI: https://drawne.com/wordpress-anti-clickjack-plugin/
 * Description: Plugin to prevent your site from being clickjacked by adding the X-Frame-Options and Content-Security-Policy frame-ancestors headers plus OWASP's legacy browser frame breaking script.
 * Version: 1.9.0
 * Requires at least: 5.0
 * Requires PHP: 7.0
 * Text Domain: wp-anti-clickjack
 * Author: Andy Feliciotti
 * Author URI: https://drawne.com
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit; // Exit if accessed directly.
}

class wp_anticlickjack {

	/** Plugin version, for the admin script. */
	const VERSION = '1.9.0';

	/** Option holding the allowed origins saved on Settings > Anti-Clickjack. */
	const OPTION = 'wp_anti_clickjack_allowed_origins';

	/** ClickJack Test's API, used by the "Check from outside" button. */
	const EXTERNAL_CHECK_API = 'https://clickjacktest.com/api/test-clickjacking';

	public function __construct() {
		// Filters are read per request in the callbacks, never here: plugins load
		// before the theme, so a filter added in functions.php would be missed.
		// Late priority, so framing headers other plugins send on this hook are seen and kept.
		add_action( 'send_headers', array( $this, 'send_frame_headers' ), 99 );
		add_action( 'admin_head', array( $this, 'include_anticlickjack_script' ) );
		add_action( 'wp_head', array( $this, 'include_anticlickjack_script' ) );
		add_action( 'login_head', array( $this, 'include_anticlickjack_script' ) );
		add_filter( 'site_status_tests', array( $this, 'register_site_health_test' ) );
		add_action( 'rest_api_init', array( $this, 'register_rest_routes' ) );
		add_action( 'admin_menu', array( $this, 'add_settings_page' ) );
		add_action( 'admin_init', array( $this, 'register_settings' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_admin_script' ) );
		add_filter( 'plugin_action_links_' . plugin_basename( __FILE__ ), array( $this, 'add_action_links' ) );
		add_filter( 'network_admin_plugin_action_links_' . plugin_basename( __FILE__ ), array( $this, 'add_action_links' ) );
	}

	/**
	 * Sends the framing headers on front-end pages. WordPress core already
	 * sends them on admin and login screens.
	 *
	 * @param WP|null $wp Current request object, passed by the send_headers action.
	 */
	public function send_frame_headers( $wp = null ) {
		if ( headers_sent() || ! apply_filters( 'wp_anti_clickjack_x_frame_options_header', true ) ) {
			return;
		}

		// Post embeds (/embed/ and ?embed=true) exist so other sites can frame them.
		if ( ! $wp instanceof WP ) {
			$wp = isset( $GLOBALS['wp'] ) ? $GLOBALS['wp'] : null;
		}
		if ( $wp instanceof WP && isset( $wp->query_vars['embed'] ) ) {
			return;
		}

		// A framing header the site or another plugin already sends wins: it may be
		// stricter (X-Frame-Options: DENY) or allow other sites on purpose, and adding
		// either header here would loosen it (browsers prefer frame-ancestors) or narrow it.
		foreach ( headers_list() as $header ) {
			if ( 0 === stripos( $header, 'X-Frame-Options:' ) || ( 0 === stripos( $header, 'Content-Security-Policy:' ) && false !== stripos( $header, 'frame-ancestors' ) ) ) {
				return;
			}
		}

		// Browsers that support frame-ancestors ignore X-Frame-Options, so allowed
		// origins still work there; X-Frame-Options only protects older browsers.
		header( 'X-Frame-Options: SAMEORIGIN' );
		// Its own policy (replace = false): a Content-Security-Policy the site already sends stays in place.
		header( 'Content-Security-Policy: frame-ancestors ' . implode( ' ', array_merge( array( "'self'" ), $this->allowed_origins() ) ), false );
	}

	/**
	 * Prints OWASP's legacy browser frame breaking script.
	 */
	public function include_anticlickjack_script() {
		$display = ! is_customize_preview() && ! wp_is_json_request() && ! $this->is_amp() && ! $this->is_editor_frame();

		/**
		 * Filters whether to print the frame breaking script on the current page.
		 * Runs last, so returning false always turns the script off.
		 *
		 * @param bool $display Whether the script will be printed.
		 */
		if ( ! apply_filters( 'wp_anti_clickjack', $display ) ) {
			return;
		}

		// Hides the page, then shows it again unless another site frames it. Allowed
		// origins are checked with location.ancestorOrigins (every ancestor, Chrome and
		// Safari) or, where that's missing, the referrer (direct parent, Firefox).
		$script = '(function () {
	var allowed = ' . wp_json_encode( $this->allowed_origins() ) . ';
	var style = document.createElement("style");
	style.id = "antiClickjack";
	style.textContent = "body{display:none !important;}";
	document.getElementsByTagName("head")[0].appendChild(style);

	function show() {
		style.parentNode.removeChild(style);
	}

	function isAllowed(origin) {
		if (origin === location.protocol + "//" + location.host) {
			return true;
		}
		for (var i = 0; i < allowed.length; i++) {
			var star = allowed[i].indexOf("://*.");
			if (allowed[i] === origin) {
				return true;
			}
			if (star > -1) {
				var scheme = allowed[i].slice(0, star + 3);
				var suffix = allowed[i].slice(star + 4);
				if (origin.indexOf(scheme) === 0 && origin.length > scheme.length + suffix.length && origin.slice(-suffix.length) === suffix) {
					return true;
				}
			}
		}
		return false;
	}

	var sameOrigin = false;
	try {
		sameOrigin = top.document.domain === document.domain;
	} catch (e) {}
	if (sameOrigin) {
		return show();
	}

	if (allowed.length) {
		var ancestors = [];
		if (location.ancestorOrigins) {
			for (var i = 0; i < location.ancestorOrigins.length; i++) {
				ancestors.push(location.ancestorOrigins[i]);
			}
		} else {
			var referrer = /^[a-z][a-z0-9+.-]*:\/\/[^\/?#]+/i.exec(document.referrer);
			if (referrer) {
				ancestors.push(referrer[0]);
			}
		}
		var ok = ancestors.length > 0;
		for (var j = 0; j < ancestors.length; j++) {
			if (!isAllowed(ancestors[j])) {
				ok = false;
			}
		}
		if (ok) {
			return show();
		}
	}

	top.location = self.location;
})();';

		// The inline script API (WordPress 5.7+) lets Content-Security-Policy
		// plugins add a nonce through the wp_inline_script_attributes filter.
		if ( function_exists( 'wp_print_inline_script_tag' ) ) {
			wp_print_inline_script_tag( $script, array( 'id' => 'wp-anti-clickjack' ) );
		} else {
			echo '<script id="wp-anti-clickjack">' . $script . '</script>' . "\n"; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Static script; origins are validated in allowed_origins().
		}
	}

	/**
	 * Origins allowed to frame the site besides the site itself: wp-admin's origin
	 * when it differs from the site's (so page builders and previews keep working),
	 * the ones saved on Settings > Anti-Clickjack, and any from the
	 * wp_anti_clickjack_allowed_origins filter.
	 *
	 * @return string[] Origins such as https://example.com or https://*.example.com.
	 */
	private function allowed_origins() {
		$origins = array();
		$admin   = $this->admin_origin();
		if ( '' !== $admin ) {
			$origins[] = $admin;
		}
		$origins = array_merge( $origins, (array) get_option( self::OPTION, array() ) );

		/**
		 * Filters the origins allowed to put the site in a frame, in addition to the
		 * site itself. Entries can be origins or full URLs, and may use a leading
		 * wildcard for subdomains ('https://*.example.com'). Invalid entries are dropped.
		 *
		 * @param string[] $origins Allowed origins: wp-admin's origin when it differs from the site's,
		 *                          then the ones saved on Settings > Anti-Clickjack.
		 */
		$filtered = apply_filters( 'wp_anti_clickjack_allowed_origins', $origins );

		$allowed = array();
		foreach ( (array) $filtered as $entry ) {
			$origin = is_string( $entry ) ? $this->to_origin( $entry ) : '';
			if ( '' !== $origin && ! in_array( $origin, $allowed, true ) ) {
				$allowed[] = $origin;
			}
		}
		return $allowed;
	}

	/**
	 * wp-admin's origin when it differs from the site's, otherwise ''.
	 *
	 * @return string
	 */
	private function admin_origin() {
		$admin = $this->to_origin( admin_url() );
		return $this->to_origin( home_url() ) !== $admin ? $admin : '';
	}

	/**
	 * Reduces a URL to an origin safe to print in a header and a script
	 * (scheme://host[:port], with an optional leading "*." on the host).
	 *
	 * @param string $url URL or origin. Without a scheme, https:// is assumed.
	 * @return string Lowercased origin, or '' when the value isn't an http(s) URL.
	 */
	private function to_origin( $url ) {
		$url = trim( $url );
		if ( false === strpos( $url, '://' ) ) {
			$url = 'https://' . $url;
		}
		if ( ! preg_match( '#^(https?)://((?:\*\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)*)(:\d{1,5})?(?:[/?\#]|$)#i', $url, $parts ) ) {
			return '';
		}
		$port = isset( $parts[3] ) ? $parts[3] : '';
		// Browsers report origins without their default port, so the script would not match ":443".
		if ( ( 'https' === strtolower( $parts[1] ) && ':443' === $port ) || ( 'http' === strtolower( $parts[1] ) && ':80' === $port ) ) {
			$port = '';
		}
		return strtolower( $parts[1] . '://' . $parts[2] ) . $port;
	}

	/**
	 * Whether this is an AMP page, where custom scripts aren't allowed.
	 *
	 * @return bool
	 */
	private function is_amp() {
		// The AMP plugin warns when these run before the query is parsed (admin and login screens).
		if ( ! did_action( 'parse_query' ) ) {
			return false;
		}
		if ( function_exists( 'amp_is_request' ) ) {
			return amp_is_request();
		}
		return function_exists( 'is_amp_endpoint' ) && is_amp_endpoint();
	}

	/**
	 * Whether a page builder, the site editor or a core update screen loaded
	 * this page in a frame of its own. The script only breaks frames from other
	 * origins, so this matters mostly when the editor runs on a different domain.
	 *
	 * The query strings that mark these frames are trusted only for users who
	 * can edit: anyone can add ?et_fb=1 to a URL they frame on their own site.
	 */
	private function is_editor_frame() {
		if ( ! is_user_logged_in() || ! current_user_can( 'edit_posts' ) ) {
			return false;
		}

		$exact = array(
			'vc_editable' => 'true',             // WPBakery.
			'et_fb'       => '1',                // Divi.
			'tve'         => 'true',             // Thrive Architect.
			'builder'     => 'true',             // Avada.
			'bricks'      => 'run',              // Bricks.
			'render_mode' => 'template-preview', // Elementor template preview.
		);
		foreach ( $exact as $key => $value ) {
			if ( $this->request_value( $key ) === $value ) {
				return true;
			}
		}

		// Present with any value: Breakdance, Oxygen, Spectra / Starter Templates,
		// and block editor preview frames.
		$present = array( 'breakdance', 'breakdance_iframe', 'ct_builder', 'oxygen_iframe', 'spectra', 'starter-templates-iframe', 'editor_frame', 'block-editor' );
		foreach ( $present as $key ) {
			if ( ! empty( $this->request_value( $key ) ) ) {
				return true;
			}
		}

		// Site editor canvas.
		if ( ! empty( $this->request_value( 'postType' ) ) && ! empty( $this->request_value( 'canvas' ) ) ) {
			return true;
		}

		// Plugin and theme update screens run inside a frame.
		if ( in_array( $this->request_value( 'action' ), array( 'do-plugin-upgrade', 'do-theme-upgrade', 'update-selected', 'update-selected-themes' ), true ) ) {
			return true;
		}

		// Cornerstone.
		if ( did_action( 'cs_before_preview_frame' ) ) {
			return true;
		}

		// Elementor.
		if ( class_exists( '\Elementor\Plugin' ) && isset( \Elementor\Plugin::$instance ) ) {
			$elementor = \Elementor\Plugin::$instance;
			if ( ( isset( $elementor->preview ) && $elementor->preview->is_preview_mode() ) || ( isset( $elementor->editor ) && $elementor->editor->is_edit_mode() ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * A request parameter as a sanitized string, or '' when absent.
	 *
	 * @param string $key Parameter name.
	 * @return string
	 */
	private function request_value( $key ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only check of which editor loaded the page; nothing is saved.
		if ( ! isset( $_REQUEST[ $key ] ) || ! is_string( $_REQUEST[ $key ] ) ) {
			return '';
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- See above.
		return sanitize_text_field( wp_unslash( $_REQUEST[ $key ] ) );
	}

	/**
	 * Adds a Site Health test that checks the headers visitors actually receive.
	 * Page caches, CDNs and server settings can drop or duplicate them.
	 *
	 * @param array $tests Site Health tests.
	 * @return array
	 */
	public function register_site_health_test( $tests ) {
		// REST-based background tests need WordPress 5.6.
		if ( version_compare( get_bloginfo( 'version' ), '5.6', '>=' ) ) {
			$tests['async']['wp_anti_clickjack_headers'] = array(
				'label'             => __( 'Clickjacking protection headers', 'wp-anti-clickjack' ),
				'test'              => rest_url( 'wp-anti-clickjack/v1/site-health' ),
				'has_rest'          => true,
				'async_direct_test' => array( $this, 'site_health_result' ),
			);
		}
		return $tests;
	}

	/**
	 * REST routes for the Site Health test (run in the background by the Site
	 * Health screen) and the "Check from outside" button.
	 */
	public function register_rest_routes() {
		if ( version_compare( get_bloginfo( 'version' ), '5.6', '>=' ) ) {
			register_rest_route(
				'wp-anti-clickjack/v1',
				'/site-health',
				array(
					'methods'             => 'GET',
					'callback'            => array( $this, 'site_health_result' ),
					'permission_callback' => function () {
						return current_user_can( 'view_site_health_checks' );
					},
				)
			);
		}
		register_rest_route(
			'wp-anti-clickjack/v1',
			'/external-check',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'external_check' ),
				'permission_callback' => function () {
					return current_user_can( 'manage_options' );
				},
			)
		);
	}

	/**
	 * Requests the homepage like a visitor and reports on its framing headers.
	 *
	 * @return array Site Health test result.
	 */
	public function site_health_result() {
		$result = array(
			'label'       => __( 'Your site sends clickjacking protection headers', 'wp-anti-clickjack' ),
			'status'      => 'good',
			'badge'       => array(
				'label' => __( 'Security', 'wp-anti-clickjack' ),
				'color' => 'blue',
			),
			'description' => '',
			'actions'     => $this->external_check_controls(),
			'test'        => 'wp_anti_clickjack_headers',
		);

		$response = wp_remote_get(
			home_url( '/' ),
			array(
				'timeout'   => 10,
				'sslverify' => apply_filters( 'https_local_ssl_verify', false ),
			)
		);
		$code = wp_remote_retrieve_response_code( $response );
		if ( is_wp_error( $response ) || $code < 200 || $code >= 400 ) {
			$result['status']      = 'recommended';
			$result['label']       = __( 'Clickjacking protection headers could not be checked', 'wp-anti-clickjack' );
			$result['description'] = '<p>' . sprintf(
				/* translators: %s: error message or HTTP status code */
				esc_html__( 'Your site could not load its own homepage to check the headers visitors receive (%s). Use the test link below to check it from outside.', 'wp-anti-clickjack' ),
				esc_html( is_wp_error( $response ) ? $response->get_error_message() : 'HTTP ' . $code )
			) . '</p>';
			return $result;
		}

		$frame_options = $this->header_values( $response, 'x-frame-options' );
		$policies      = array_values(
			array_filter(
				$this->header_values( $response, 'content-security-policy' ),
				function ( $policy ) {
					return false !== stripos( $policy, 'frame-ancestors' );
				}
			)
		);
		$unique_options = array_unique( array_map( 'strtoupper', $frame_options ) );
		$valid_options  = 1 === count( $unique_options ) && in_array( reset( $unique_options ), array( 'DENY', 'SAMEORIGIN' ), true );

		$seen = array();
		foreach ( $frame_options as $value ) {
			$seen[] = 'X-Frame-Options: ' . $value;
		}
		foreach ( $policies as $policy ) {
			$seen[] = 'Content-Security-Policy: ' . $policy;
		}
		$seen_list = $seen ? '<ul><li><code>' . implode( '</code></li><li><code>', array_map( 'esc_html', $seen ) ) . '</code></li></ul>' : '';

		if ( ! $policies && ! $valid_options ) {
			$turned_off            = ! apply_filters( 'wp_anti_clickjack_x_frame_options_header', true );
			$result['status']      = $turned_off ? 'recommended' : 'critical';
			$result['label']       = __( 'Other sites can put your homepage in a frame', 'wp-anti-clickjack' );
			$result['description'] = '<p>' . esc_html__( 'Your homepage was loaded without an X-Frame-Options or Content-Security-Policy frame-ancestors header, so browsers will let other sites frame it. The frame breaking script still hides the page from most of those frames, but the headers are the main protection.', 'wp-anti-clickjack' ) . '</p>';
			$result['description'] .= '<p>' . ( $turned_off
				? esc_html__( 'The headers are turned off with the wp_anti_clickjack_x_frame_options_header filter.', 'wp-anti-clickjack' )
				: esc_html__( 'A page cache, CDN or server setting may be serving pages without the headers. Add them in that layer, or have it pass through the headers WordPress sends.', 'wp-anti-clickjack' )
			) . '</p>' . $seen_list;
			return $result;
		}

		if ( count( $policies ) > 1 ) {
			$result['status']      = 'recommended';
			$result['label']       = __( 'Your site sends more than one frame-ancestors policy', 'wp-anti-clickjack' );
			$result['description'] = '<p>' . esc_html__( 'Browsers apply every Content-Security-Policy they receive, so a site can only frame yours if all of these policies allow it. This usually means the server or another plugin also sets one. If that one should decide, turn this plugin\'s headers off with the wp_anti_clickjack_x_frame_options_header filter.', 'wp-anti-clickjack' ) . '</p>' . $seen_list;
			return $result;
		}

		if ( count( $frame_options ) > 0 && ! $valid_options ) {
			$result['status']      = 'recommended';
			$result['label']       = __( 'Your site sends conflicting X-Frame-Options values', 'wp-anti-clickjack' );
			$result['description'] = '<p>' . esc_html__( 'Browsers ignore X-Frame-Options when it has more than one value or an unknown one. Your frame-ancestors policy still protects modern browsers, but the server or another plugin is also sending X-Frame-Options.', 'wp-anti-clickjack' ) . '</p>' . $seen_list;
			return $result;
		}

		$result['description'] = '<p>' . esc_html__( 'Your homepage was loaded like a visitor would load it, and it tells browsers not to let other sites put it in a frame:', 'wp-anti-clickjack' ) . '</p>' . $seen_list;
		return $result;
	}

	/**
	 * All values of a response header, one entry per value. Repeated headers and
	 * comma-separated values are both split (commas also separate CSP policies).
	 *
	 * @param array  $response HTTP response.
	 * @param string $name     Header name.
	 * @return string[]
	 */
	private function header_values( $response, $name ) {
		$values = array();
		foreach ( (array) wp_remote_retrieve_header( $response, $name ) as $line ) {
			foreach ( explode( ',', $line ) as $value ) {
				$value = trim( $value );
				if ( '' !== $value ) {
					$values[] = $value;
				}
			}
		}
		return $values;
	}

	/**
	 * Adds "Settings" and "Test your site" links to the plugin's row on the Plugins screen.
	 *
	 * @param string[] $links Action links.
	 * @return string[]
	 */
	public function add_action_links( $links ) {
		if ( ! is_network_admin() && current_user_can( 'manage_options' ) ) {
			array_unshift( $links, sprintf( '<a href="%1$s">%2$s</a>', esc_url( admin_url( 'options-general.php?page=wp-anti-clickjack' ) ), esc_html__( 'Settings', 'wp-anti-clickjack' ) ) );
		}
		$links[] = sprintf(
			'<a href="%1$s" target="_blank" rel="noopener">%2$s</a>',
			esc_url( $this->test_url() ),
			esc_html__( 'Test your site', 'wp-anti-clickjack' )
		);
		return $links;
	}

	/**
	 * Asks ClickJack Test to load the homepage from the internet and report the
	 * framing headers it gets, which shows what a CDN or proxy in front of the site
	 * serves. Only runs when an administrator clicks "Check from outside".
	 *
	 * @return array Status ('good', 'critical' or 'error'), message and headers seen.
	 */
	public function external_check() {
		$response = wp_remote_post(
			self::EXTERNAL_CHECK_API,
			array(
				'timeout' => 25,
				'headers' => array( 'Content-Type' => 'application/json' ),
				'body'    => wp_json_encode( array( 'url' => home_url( '/' ) ) ),
			)
		);
		if ( is_wp_error( $response ) ) {
			return array(
				'status'  => 'error',
				/* translators: %s: error message */
				'message' => sprintf( __( 'Could not reach ClickJack Test: %s', 'wp-anti-clickjack' ), $response->get_error_message() ),
			);
		}

		$data = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( ! is_array( $data ) || ( ! isset( $data['error'] ) && ! isset( $data['vulnerable'] ) ) ) {
			return array(
				'status'  => 'error',
				'message' => __( 'ClickJack Test sent a response this plugin does not understand. Try the full test instead.', 'wp-anti-clickjack' ),
			);
		}
		if ( isset( $data['error'] ) ) {
			// ClickJack Test refuses private, local and unusual-port addresses.
			$private = is_string( $data['error'] ) && false !== stripos( $data['error'], 'not allowed' );
			return array(
				'status'  => 'error',
				'message' => $private
					/* translators: %s: site address */
					? sprintf( __( 'ClickJack Test can only check sites it can reach from the internet, and %s is a local or private address.', 'wp-anti-clickjack' ), home_url( '/' ) )
					/* translators: %s: error message from ClickJack Test */
					: sprintf( __( 'ClickJack Test could not check your site: %s', 'wp-anti-clickjack' ), is_string( $data['error'] ) ? $data['error'] : '' ),
			);
		}

		$headers = array();
		if ( isset( $data['xFrameOptions'] ) && is_string( $data['xFrameOptions'] ) && 'Not set' !== $data['xFrameOptions'] ) {
			$headers[] = 'X-Frame-Options: ' . $data['xFrameOptions'];
		}
		if ( ! empty( $data['cspHasFrameAncestors'] ) && isset( $data['contentSecurityPolicy'] ) && is_string( $data['contentSecurityPolicy'] ) ) {
			$headers[] = 'Content-Security-Policy: ' . $data['contentSecurityPolicy'];
		}
		if ( empty( $data['vulnerable'] ) ) {
			$message = __( 'Protected: loaded from the internet, your homepage tells browsers not to let other sites frame it.', 'wp-anti-clickjack' );
		} elseif ( ! apply_filters( 'wp_anti_clickjack_x_frame_options_header', true ) ) {
			$message = __( 'Not protected: loaded from the internet, your homepage has no framing headers, because they are turned off with the wp_anti_clickjack_x_frame_options_header filter.', 'wp-anti-clickjack' );
		} else {
			$message = __( 'Not protected: loaded from the internet, your homepage has no framing headers. A CDN, proxy or page cache in front of your site is likely serving it without them.', 'wp-anti-clickjack' );
		}
		return array(
			'status'  => empty( $data['vulnerable'] ) ? 'good' : 'critical',
			'message' => $message,
			'headers' => $headers,
		);
	}

	/**
	 * "Check from outside" button, its result area and a link to the full test.
	 *
	 * @return string HTML.
	 */
	private function external_check_controls() {
		return '<div class="wp-anti-clickjack-external">'
			. '<p><button type="button" class="button wp-anti-clickjack-external-check">' . esc_html__( 'Check from outside', 'wp-anti-clickjack' ) . '</button></p>'
			. '<div class="wp-anti-clickjack-external-result" aria-live="polite"></div>'
			. '<p class="description">' . sprintf(
				/* translators: %s: site address */
				esc_html__( 'Sends your homepage address (%s) to ClickJack Test (clickjacktest.com), which loads it from the internet the way visitors do, through any CDN or proxy.', 'wp-anti-clickjack' ),
				'<code>' . esc_html( home_url( '/' ) ) . '</code>'
			) . '</p>'
			. sprintf(
				'<p><a href="%1$s" target="_blank" rel="noopener">%2$s<span class="screen-reader-text"> %3$s</span><span aria-hidden="true" class="dashicons dashicons-external"></span></a></p>',
				esc_url( $this->test_url() ),
				esc_html__( 'See the full report on ClickJack Test', 'wp-anti-clickjack' ),
				esc_html__( '(opens in a new tab)', 'wp-anti-clickjack' )
			)
			. '</div>';
	}

	/**
	 * Loads the "Check from outside" button script on the Site Health and settings screens.
	 *
	 * @param string $hook_suffix Current admin screen.
	 */
	public function enqueue_admin_script( $hook_suffix ) {
		if ( 'site-health.php' !== $hook_suffix && 'settings_page_wp-anti-clickjack' !== $hook_suffix ) {
			return;
		}
		$text = array(
			'checking' => __( 'Checking from outside...', 'wp-anti-clickjack' ),
			'failed'   => __( 'The check failed. Try the full report instead.', 'wp-anti-clickjack' ),
		);
		wp_register_script( 'wp-anti-clickjack-admin', false, array( 'wp-api-fetch' ), self::VERSION, true );
		wp_enqueue_script( 'wp-anti-clickjack-admin' );
		// Results come from another service, so they are added as text, never as HTML.
		wp_add_inline_script(
			'wp-anti-clickjack-admin',
			'(function () {
	var text = ' . wp_json_encode( $text ) . ';
	document.addEventListener("click", function (event) {
		var button = event.target && event.target.closest ? event.target.closest(".wp-anti-clickjack-external-check") : null;
		if (!button) {
			return;
		}
		var result = button.closest(".wp-anti-clickjack-external").querySelector(".wp-anti-clickjack-external-result");
		button.disabled = true;
		result.textContent = text.checking;
		wp.apiFetch({ path: "/wp-anti-clickjack/v1/external-check", method: "POST" }).then(function (data) {
			var message = document.createElement("p");
			message.textContent = data.message;
			result.textContent = "";
			result.appendChild(message);
			(data.headers || []).forEach(function (header) {
				var code = document.createElement("code");
				code.textContent = header;
				var line = document.createElement("p");
				line.appendChild(code);
				result.appendChild(line);
			});
		}, function (error) {
			result.textContent = (error && error.message) || text.failed;
		}).then(function () {
			button.disabled = false;
		});
	});
})();'
		);
	}

	/**
	 * Adds Settings > Anti-Clickjack.
	 */
	public function add_settings_page() {
		add_options_page(
			__( 'Anti-Clickjack', 'wp-anti-clickjack' ),
			__( 'Anti-Clickjack', 'wp-anti-clickjack' ),
			'manage_options',
			'wp-anti-clickjack',
			array( $this, 'render_settings_page' )
		);
	}

	/**
	 * Registers the allowed origins setting.
	 */
	public function register_settings() {
		register_setting(
			'wp_anti_clickjack',
			self::OPTION,
			array(
				'type'              => 'array',
				'sanitize_callback' => array( $this, 'sanitize_allowed_origins' ),
				'default'           => array(),
			)
		);
	}

	/**
	 * Turns the settings textarea into a list of origins, reporting entries that
	 * aren't site addresses.
	 *
	 * @param string|array $value One entry per line (or comma separated), or an already saved list.
	 * @return string[]
	 */
	public function sanitize_allowed_origins( $value ) {
		$entries = is_array( $value ) ? $value : array_filter( array_map( 'trim', preg_split( '/[\r\n,]+/', (string) $value ) ), 'strlen' );
		$origins = array();
		$skipped = array();
		foreach ( $entries as $entry ) {
			$origin = is_string( $entry ) ? $this->to_origin( $entry ) : '';
			if ( '' === $origin ) {
				$skipped[] = is_scalar( $entry ) ? (string) $entry : '';
			} elseif ( ! in_array( $origin, $origins, true ) ) {
				$origins[] = $origin;
			}
		}
		// WordPress runs this twice when the option is first created; only the form input (a string) is reported.
		if ( $skipped && ! is_array( $value ) ) {
			add_settings_error(
				self::OPTION,
				'invalid-origins',
				/* translators: %s: comma-separated list of entries */
				sprintf( esc_html__( 'Saved, except these entries, which are not site addresses: %s', 'wp-anti-clickjack' ), esc_html( implode( ', ', $skipped ) ) ),
				'warning'
			);
		}
		return $origins;
	}

	/**
	 * Settings > Anti-Clickjack.
	 */
	public function render_settings_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$saved      = (array) get_option( self::OPTION, array() );
		$admin      = $this->admin_origin();
		$allowed    = $this->allowed_origins();
		$from_code  = array_values( array_diff( $allowed, $saved, array( $admin ) ) );
		$headers_on = apply_filters( 'wp_anti_clickjack_x_frame_options_header', true );
		?>
		<div class="wrap">
			<h1><?php echo esc_html( get_admin_page_title() ); ?></h1>
			<p><?php esc_html_e( 'WP Anti-Clickjack stops other sites from putting your site in a frame, where they could trick visitors into clicking things they cannot see. Your own site can always frame itself.', 'wp-anti-clickjack' ); ?></p>

			<form method="post" action="options.php">
				<?php settings_fields( 'wp_anti_clickjack' ); ?>
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><label for="wp-anti-clickjack-allowed"><?php esc_html_e( 'Sites allowed to frame this site', 'wp-anti-clickjack' ); ?></label></th>
						<td>
							<textarea id="wp-anti-clickjack-allowed" name="<?php echo esc_attr( self::OPTION ); ?>" rows="5" class="large-text code" aria-describedby="wp-anti-clickjack-allowed-help"><?php echo esc_textarea( implode( "\n", $saved ) ); ?></textarea>
							<p class="description" id="wp-anti-clickjack-allowed-help"><?php esc_html_e( 'One per line, like https://partner.example. Use https://*.example.com to allow every subdomain. Leave empty unless another site needs to show yours in a frame.', 'wp-anti-clickjack' ); ?></p>
							<?php if ( '' !== $admin ) : ?>
								<p class="description">
									<?php
									/* translators: %s: admin origin */
									printf( esc_html__( 'Your WordPress admin (%s) is on a different domain, so it is always allowed.', 'wp-anti-clickjack' ), '<code>' . esc_html( $admin ) . '</code>' );
									?>
								</p>
							<?php endif; ?>
							<?php if ( $from_code ) : ?>
								<p class="description">
									<?php
									/* translators: %s: list of origins */
									printf( esc_html__( 'Also allowed by code (the wp_anti_clickjack_allowed_origins filter): %s', 'wp-anti-clickjack' ), '<code>' . implode( '</code>, <code>', array_map( 'esc_html', $from_code ) ) . '</code>' );
									?>
								</p>
							<?php endif; ?>
						</td>
					</tr>
				</table>
				<?php submit_button(); ?>
			</form>

			<h2><?php esc_html_e( 'Headers your pages send', 'wp-anti-clickjack' ); ?></h2>
			<?php if ( $headers_on ) : ?>
				<p><code>X-Frame-Options: SAMEORIGIN</code><br><code><?php echo esc_html( 'Content-Security-Policy: frame-ancestors ' . implode( ' ', array_merge( array( "'self'" ), $allowed ) ) ); ?></code></p>
				<p class="description"><?php esc_html_e( 'If your server, CDN or another plugin already sends a framing header, it is kept and these are not added.', 'wp-anti-clickjack' ); ?></p>
			<?php else : ?>
				<p><?php esc_html_e( 'The headers are turned off with the wp_anti_clickjack_x_frame_options_header filter. Only the frame breaking script protects your pages.', 'wp-anti-clickjack' ); ?></p>
			<?php endif; ?>

			<h2><?php esc_html_e( 'Check your protection', 'wp-anti-clickjack' ); ?></h2>
			<?php
			echo $this->external_check_controls(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Built from escaped parts.
			if ( version_compare( get_bloginfo( 'version' ), '5.6', '>=' ) ) {
				/* translators: %s: Site Health screen URL */
				echo '<p>' . wp_kses_post( sprintf( __( '<a href="%s">Site Health</a> also checks the headers your server sends on each visit.', 'wp-anti-clickjack' ), esc_url( admin_url( 'site-health.php' ) ) ) ) . '</p>';
			}
			?>
		</div>
		<?php
	}

	/**
	 * Removes the saved setting when the plugin is deleted.
	 */
	public static function uninstall() {
		delete_option( self::OPTION );
	}

	/**
	 * ClickJack Test link that tests this site's homepage when opened.
	 *
	 * @return string
	 */
	private function test_url() {
		return 'https://clickjacktest.com/?url=' . rawurlencode( home_url( '/' ) );
	}
}

register_uninstall_hook( __FILE__, array( 'wp_anticlickjack', 'uninstall' ) );
new wp_anticlickjack();
