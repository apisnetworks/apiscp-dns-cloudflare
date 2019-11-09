<?php declare(strict_types=1);
	/**
	 * Copyright (C) Apis Networks, Inc - All Rights Reserved.
	 *
	 * Unauthorized copying of this file, via any medium, is
	 * strictly prohibited without consent. Any dissemination of
	 * material herein is prohibited.
	 *
	 * For licensing inquiries email <licensing@apisnetworks.com>
	 *
	 * Written by Matt Saladna <matt@apisnetworks.com>, November 2019
	 */

	namespace Opcenter\Dns\Providers\Cloudflare\Extensions;

	use Cloudflare\API\Adapter\Adapter;
	use Cloudflare\API\Endpoints\User;
	use Cloudflare\API\Traits\BodyAccessorTrait;

	class TokenVerify extends User
	{
		use BodyAccessorTrait;

		protected $adapter;

		public function __construct(Adapter $adapter)
		{
			$this->adapter = $adapter;
			parent::__construct($adapter);
		}

		public function verifyToken(): bool
		{
			$response = $this->adapter->get('user/tokens/verify');
			$this->body = json_decode($response->getBody()->getContents());

			return true;
		}
	}