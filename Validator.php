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
			// accept $var as a single token or as an array
			if (is_string($var)) {
				return static::keyValid(null, $var);
			}

			if (!isset($var['key'])) {
				return error("Cloudflare key must provided");
			}
			if (isset($var['email']) && !ctype_xdigit($var['key'])) {
				return error("Key must be in hexadecimal");
			}
			if (isset($var['email']) && !preg_match(\Regex::EMAIL, $var['email'])) {
				return error("Email address not properly formed");
			}

			foreach (['proxy', 'jumpstart'] as $name) {
				if (!isset($var[$name])) {
					// default
					$var[$name] = true;
				} else {
					if ($var[$name] === 1 || $var[$name] === "1") {
						$var[$name] = true;
					} else if ($var[$name] === 0 || $var[$name] === "0") {
						$var[$name] = false;
					}
					if (!\is_bool($var[$name])) {
						return error("`%s' must be true or false", $name);
					}
				}

			}

			if (!static::keyValid($var['email'] ?? null, (string)$var['key'])) {
				return false;
			}

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
