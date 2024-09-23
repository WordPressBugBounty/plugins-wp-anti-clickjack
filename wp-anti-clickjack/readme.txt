=== WP Anti-Clickjack ===
Contributors: someguy9
Donate link: https://www.buymeacoffee.com/someguy
Tags: anti click jacking, security, Browser Frame Breaking Script, clickjacking
Requires at least: 5.0.0
Tested up to: 6.5
Stable tag: 1.7.9
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

Protect Your WordPress Site From Clickjacking Attacks by Adding the X-Frame-Options Header and Owasp's Legacy Browser Frame Breaking Script.

== Description ==

WP Anti-Clickjack is a powerful security plugin that helps prevent your WordPress site from being vulnerable to clickjacking attacks. Clickjacking is a malicious technique where an attacker tricks users into clicking on a concealed link or button by overlaying it on your legitimate website.

This plugin implements two key defense mechanisms:

1. **X-Frame-Options Header**: The plugin adds the `X-Frame-Options: SAMEORIGIN` HTTP header to your site's responses. This header instructs web browsers to prevent other websites from embedding your site within an iframe, effectively blocking clickjacking attempts.

2. **OWASP's Legacy Browser Frame Breaking Script**: The plugin includes a modified version of OWASP's legacy browser frame breaking script. This script prevents other sites from putting your site in an iframe, even in browsers that don't support the X-Frame-Options header. The script is optimized to work seamlessly in browsers with and without JavaScript enabled.

By combining these two security measures, WP Anti-Clickjack provides comprehensive protection against clickjacking attacks, ensuring the safety and integrity of your WordPress site.

For more information about clickjacking defense techniques, refer to the [OWASP Clickjacking Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html).

= Features =

- Adds the `X-Frame-Options: SAMEORIGIN` HTTP header to prevent clickjacking
- Includes a modified version of OWASP's legacy browser frame breaking script
- Compatible with popular page builders and editors like Elementor, Divi, WPBakery, and more
- Provides filters to disable the anti-clickjacking measures when needed
- Easy to install and configure
- Regularly updated and tested with the latest WordPress versions

= Additional Details =

If you need to disable the clickjacking JavaScript on a specific page, you can use the following filter in your theme's `functions.php` file:

`add_filter('wp_anti_clickjack', '__return_false');`

To disable the clickjacking X-Frame-Options HTTP header, use this filter in your theme's `functions.php` file:

`add_filter('wp_anti_clickjack_x_frame_options_header', '__return_false');`

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

= Can I customize the anti-clickjacking behavior? =

Yes, the plugin provides filters that allow you to disable the clickjacking JavaScript and the X-Frame-Options header when needed. You can use these filters in your theme's `functions.php` file to fine-tune the plugin's behavior.

== Frequently Asked Questions ==


== Changelog ==

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
