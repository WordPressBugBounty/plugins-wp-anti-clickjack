=== WP Anti-Clickjack ===
Contributors: someguy9
Donate link: https://www.buymeacoffee.com/someguy
Tags: anti click jacking, security, Browser Frame Breaking Script, clickjacking
Requires at least: 5.0
Tested up to: 7.1
Requires PHP: 7.0
Stable tag: 1.9.0
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

Protect your WordPress site from clickjacking with X-Frame-Options and CSP frame-ancestors headers plus a frame breaking script.

== Description ==

WP Anti-Clickjack is a powerful security plugin that helps prevent your WordPress site from being vulnerable to clickjacking attacks. Clickjacking is a malicious technique where an attacker tricks users into clicking on a concealed link or button by overlaying it on your legitimate website.

This plugin implements two key defense mechanisms:

1. **Frame protection headers**: The plugin adds the `X-Frame-Options: SAMEORIGIN` and `Content-Security-Policy: frame-ancestors 'self'` HTTP headers to your site's pages. They instruct web browsers to prevent other websites from embedding your site within an iframe, effectively blocking clickjacking attempts. A Content-Security-Policy your site already sends is left in place, and WordPress post embeds stay embeddable on other sites.

2. **OWASP's Legacy Browser Frame Breaking Script**: The plugin includes a modified version of OWASP's legacy browser frame breaking script. This script prevents other sites from putting your site in an iframe, even in browsers that don't support the X-Frame-Options header. The script is optimized to work seamlessly in browsers with and without JavaScript enabled.

By combining these two security measures, WP Anti-Clickjack provides comprehensive protection against clickjacking attacks, ensuring the safety and integrity of your WordPress site.

For more information about clickjacking defense techniques, refer to the [OWASP Clickjacking Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html).

= Features =

- Adds the `X-Frame-Options: SAMEORIGIN` and `Content-Security-Policy: frame-ancestors 'self'` HTTP headers to prevent clickjacking
- Works alongside your existing Content-Security-Policy, including nonce-based policies, and keeps framing headers your server or another plugin already sends
- Settings > Anti-Clickjack screen to let sites you choose (like your other domains or a partner) frame your site, also available as the `wp_anti_clickjack_allowed_origins` filter
- Site Health check that loads your homepage like a visitor and warns if a page cache, CDN or server setting drops or duplicates the headers
- "Check from outside" button that has [ClickJack Test](https://clickjacktest.com) load your homepage from the internet, through your CDN, and shows what it sees
- "Test your site" link on the Plugins screen
- Includes a modified version of OWASP's legacy browser frame breaking script
- Compatible with popular page builders and editors like Elementor, Divi, WPBakery, Bricks, Breakdance, Oxygen, and more
- Provides filters to disable the anti-clickjacking measures when needed
- Easy to install and configure
- Regularly updated and tested with the latest WordPress versions

= Additional Details =

To disable the clickjacking JavaScript, use the following filter in your theme's `functions.php` file. It receives `true` or `false` and runs last, so you can also return `false` only on specific pages:

`add_filter('wp_anti_clickjack', '__return_false');`

To disable the clickjacking HTTP headers (`X-Frame-Options` and `Content-Security-Policy: frame-ancestors`), use this filter in your theme's `functions.php` file:

`add_filter('wp_anti_clickjack_x_frame_options_header', '__return_false');`

To let other sites put your site in a frame, add them under Settings > Anti-Clickjack, one per line. Developers can use this filter instead (it also receives the sites saved in the settings). Wildcards work for subdomains, and the frame breaking script allows the same sites:

`add_filter( 'wp_anti_clickjack_allowed_origins', function ( $origins ) {
	$origins[] = 'https://partner.example';
	$origins[] = 'https://*.example.com';
	return $origins;
} );`

If your WordPress admin runs on a different domain than your site, that domain is allowed automatically so page builders and previews keep working.

Page builder and editor previews are detected only for logged-in users who can edit posts, so a visitor cannot switch the protection off by adding a page builder parameter to a URL.

If your server, CDN or another plugin already sends an `X-Frame-Options` header or a `frame-ancestors` policy, the plugin leaves them as they are and doesn't add its own.

== Installation ==

1. Download the plugin from the WordPress.org repository or your WordPress admin dashboard.
2. Upload the plugin files to the `/wp-content/plugins/wp-anti-clickjack` directory, or install the plugin through the WordPress admin interface.
3. Activate the plugin through the 'Plugins' screen in your WordPress admin.
4. The plugin will automatically add the necessary anti-clickjacking measures to your site.

== Frequently Asked Questions ==

= Does this plugin affect my site's performance? =

No, WP Anti-Clickjack is designed to have minimal impact on your site's performance. The anti-clickjacking measures are applied efficiently without causing any significant overhead.

= Is this plugin compatible with page builders and editors? =

Yes, WP Anti-Clickjack is compatible with popular page builders and editors such as Elementor, Divi, WPBakery, Thrive Architect, and more. If you encounter any compatibility issues, please contact me for assistance.

= How do I let another site put my site in a frame? =

Add its address under Settings > Anti-Clickjack, like `https://partner.example` (or `https://*.example.com` for every subdomain). Developers can use the `wp_anti_clickjack_allowed_origins` filter shown under Additional Details. The site is added to the `frame-ancestors` policy and the frame breaking script allows it too.

= How do I know the protection reaches my visitors? =

Go to Tools > Site Health. The plugin's check loads your homepage the way a visitor would and tells you if the headers are missing (often a page cache or CDN serving pages without them) or if more than one framing policy is sent. Click "Check from outside" there or under Settings > Anti-Clickjack to have ClickJack Test load your homepage from the internet, through any CDN or proxy, and show what it sees.

= Can I customize the anti-clickjacking behavior? =

Yes, the plugin provides filters that allow you to disable the clickjacking JavaScript and the X-Frame-Options header when needed. You can use these filters in your theme's `functions.php` file to fine-tune the plugin's behavior.

== External services ==

The "Check from outside" button and the "Test your site" link use [ClickJack Test](https://clickjacktest.com), a free clickjacking tester. Nothing is sent unless an administrator clicks one of them. When they do, your homepage address is sent to clickjacktest.com, which requests that address from the internet and reports the framing headers it receives. No other data about your site or its users is sent. See ClickJack Test's [terms of use](https://clickjacktest.com/terms) and [privacy policy](https://clickjacktest.com/privacy).

== Changelog ==

= 1.9.0 =
* New: let sites you choose frame your site with the `wp_anti_clickjack_allowed_origins` filter (added to the `frame-ancestors` policy and allowed by the frame breaking script)
* New: Settings > Anti-Clickjack screen to allow sites to frame yours without code, with a preview of the headers your pages send
* New: Site Health check that loads your homepage like a visitor and warns when the headers are missing, duplicated or conflicting
* New: "Check from outside" button (Site Health and settings) that has ClickJack Test load your homepage from the internet and shows what your CDN or proxy serves
* New: "Settings" and "Test your site" links on the Plugins screen
* Fixed: no longer replaces a stricter `X-Frame-Options: DENY` (or any framing header) your server or another plugin already sends
* Fixed: page builders and previews work when the WordPress admin runs on a different domain than the site
* Fixed: framing headers that other plugins send later in the same request are now seen and kept
* Fixed: the frame breaking script is skipped on AMP pages, where custom scripts aren't allowed
* Tested up to WordPress 7.1
* Fixed: no longer replaces a Content-Security-Policy that your site or another plugin already sends
* Fixed: WordPress post embeds can be shown on other sites again
* Fixed: the `wp_anti_clickjack_x_frame_options_header` filter now works from your theme's `functions.php`
* Fixed: returning `false` from the `wp_anti_clickjack` filter now turns the script off for every visitor, including visitors arriving from other sites
* Security: page builder preview parameters now skip the script only for logged-in users who can edit posts
* Sends `Content-Security-Policy: frame-ancestors 'self'` alongside `X-Frame-Options` on every supported WordPress version
* The script now prints through the WordPress inline script API, so Content-Security-Policy plugins can add a nonce to it
* Code cleanup for WordPress coding standards

= 1.8.0 =
* Tested up to WordPress 6.9
* Added support for Bricks Builder
* Added support for Breakdance Builder
* Added support for Oxygen Builder
* Added support for Spectra / Starter Templates
* Added support for Gutenberg Full Site Editor (FSE)
* Fixed bug with referrer host comparison logic
* Fixed PHP 8+ compatibility issue with parse_url() error handling
* Fixed JavaScript cross-origin exception when framed by attacker sites
* Removed deprecated language attribute from script tag

= 1.7.9 =
* Tested up to WordPress 6.5

= 1.7.8 =
* Bug fixes for same origin requests

= 1.7.7 =
* Tested up to WordPress 6.3
* Bug fix for Elementor Pro site editor

= 1.7.6 =
* Tested up to WordPress 6.2
* PHP warning bug fix

= 1.7.5 =
* Added support for Avada builder

= 1.7.4 =
* Tested up to WordPress 6.1

= 1.7.3 =
* Tested up to WordPress 6.0
* Bug fix when using the WP customizer and editing widgets

= 1.7.2 =
* Added support for Divi builder

= 1.7.1 =
* Tested up to WordPress 5.9

= 1.7.0 =
* Added HTTP header X-Frame-Options: SAMEORIGIN to further prevent clickjacking

= 1.6.5 =
* Tested up to WordPress 5.8

= 1.6.4 =
* Tested up to WordPress 5.7

= 1.6.3 =
* Support for Cornerstone Page Builder

= 1.6.2 =
* Support for WPBakery Page Builder

= 1.6.1 =
* Tested up to WordPress 5.6

= 1.6.0 =
* Added filter to disable the anti-clickjack script when needed
* Tested up to WordPress 5.5

= 1.5.4 =
* Increase WordPress supported version to 5.4

= 1.5.3 =
* Increase WordPress supported version to 5.3

= 1.5.2 =
* Bug fix for PHP warning

= 1.5.1 =
* Increase WordPress supported version to 5.2.2

= 1.5.0 =
* Bug fix when updating plugins/themes
* Support for Thrive editor

= 1.4.0 =
* Tested up to 4.8.9 and fixed conflicts with Elementor (if you are having an issue with a specific page builder please contact me)

= 1.3.0 =
* Tested up to 4.8.0

= 1.2.0 =
* Tweaked to add anti-clickjacking script to the admin pages

= 1.1.1 =
* Tested up to 4.7.2

= 1.1 =
* Bug fix causing Customizer.php to refresh constantly

= 1.0 =
* Initial Release
