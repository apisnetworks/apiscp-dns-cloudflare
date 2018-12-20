<?php declare(strict_types=1);

	/**
	 * Copyright (C) Apis Networks, Inc - All Rights Reserved.
	 *
	 * MIT License
	 *
	 * Written by Matt Saladna <matt@apisnetworks.com>, August 2018
	 */

	namespace Opcenter\Dns\Providers\Cloudflare;

	use Cloudflare\API\Endpoints\API as CFAPI;

	class Api
	{

		/**
		 * Create a Cloudflare API instance
		 *
		 * @param string $email
		 * @param string $key
		 * @param string $abstract
		 * @return CFAPI
		 */
		public static function api(string $email, string $key, string $abstract): CFAPI
		{
			$key = new \Cloudflare\API\Auth\APIKey($email, $key);
			$adapter = new \Cloudflare\API\Adapter\Guzzle($key);

			return new $abstract($adapter);
		}
	}