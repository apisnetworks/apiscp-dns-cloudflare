<?php
	declare(strict_types=1);

	/**
	 * Copyright (C) Apis Networks, Inc - All Rights Reserved.
	 *
	 * MIT License
	 *
	 * Written by Matt Saladna <matt@apisnetworks.com>, June 2017
	 */

	namespace Opcenter\Dns\Providers\Cloudflare;

	use Cloudflare\API\Endpoints\User;
	use Cloudflare\API\Endpoints\Zones;
	use GuzzleHttp\Exception\ClientException;
	use Opcenter\Dns\Contracts\ServiceProvider;
	use Opcenter\Dns\Providers\Cloudflare\Extensions\TokenVerify;
	use Opcenter\Service\ConfigurationContext;

	class Validator implements ServiceProvider
	{
		/**
		 * Validate service value
		 *
		 * @param ConfigurationContext $ctx
		 * @param                      $var service value
		 * @return bool
		 */
		public function valid(ConfigurationContext $ctx, &$var): bool
		{
			// allow dns.key in auth.yaml
			$tmp = $var ?? defined('AUTH_CLOUDFLARE_KEY') ? AUTH_CLOUDFLARE_KEY : null;
			// accept $var as a single token or as an array
			if (is_string($tmp)) {
				return static::keyValid(null, $tmp);
			}

			if (!isset($tmp['key'])) {
				return error("Cloudflare key must provided");
			}
			if (isset($tmp['email']) && !ctype_xdigit($tmp['key'])) {
				return error("Key must be in hexadecimal");
			}
			if (isset($tmp['email']) && !preg_match(\Regex::EMAIL, $tmp['email'])) {
				return error("Email address not properly formed");
			}

			foreach (['proxy', 'jumpstart'] as $name) {
				if (!isset($tmp[$name])) {
					// default
					$tmp[$name] = true;
				} else {
					if ($tmp[$name] === 1 || $tmp[$name] === "1") {
						$tmp[$name] = true;
					} else if ($tmp[$name] === 0 || $tmp[$name] === "0") {
						$tmp[$name] = false;
					}
					if (!\is_bool($tmp[$name])) {
						return error("`%s' must be true or false", $name);
					}
				}

			}

			if (!static::keyValid($tmp['email'] ?? null, (string)$tmp['key'])) {
				return false;
			}
			$var = $tmp;

			return true;
		}

		/**
		 * Given key/token is valid
		 *
		 * @param string|null $email
		 * @param string      $key
		 * @return bool
		 */
		public static function keyValid(?string $email, string $key): bool
		{
			try {
				if (!$email) {
					Api::api($email, $key, TokenVerify::class)->verifyToken();
					// ensure privileges exist to list zones
					try {
						Api::api($email, $key, Zones::class)->listZones();
					} catch (ClientException $e) {
						return error("Token lacks edit access on Zone.Zone resource");
					}
				} else {
					Api::api($email, $key, User::class)->getUserDetails();
				}
			} catch (ClientException $e) {
				$response = \json_decode($e->getResponse()->getBody()->getContents(), true);
				$reason = array_get($response, 'errors.0.error_chain.0.message', "Invalid key");

				return error("CF key failed: %s", $reason);
			}

			return true;
		}

	}
