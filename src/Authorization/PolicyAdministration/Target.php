<?php

/**
 * Copyright 2015-2019 info@neomerx.com
 * Modification Copyright 2021-2022 info@whoaphp.com
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

declare(strict_types=1);

namespace Whoa\Auth\Authorization\PolicyAdministration;

use Whoa\Auth\Contracts\Authorization\PolicyAdministration\AnyOfInterface;
use Whoa\Auth\Contracts\Authorization\PolicyAdministration\TargetInterface;

/**
 * @package Whoa\Auth
 */
class Target implements TargetInterface
{
    /**
     * @var null|string
     */
    private ?string $name;

    /**
     * @var AnyOfInterface
     */
    private AnyOfInterface $anyOff;

    /**
     * @param AnyOfInterface $anyOff
     * @param string|null $name
     */
    public function __construct(AnyOfInterface $anyOff, string $name = null)
    {
        $this->setAnyOff($anyOff)->setName($name);
    }

    /**
     * @inheritdoc
     */
    public function getAnyOf(): AnyOfInterface
    {
        return $this->anyOff;
    }

    /**
     * @inheritdoc
     */
    public function getName(): ?string
    {
        return $this->name;
    }

    /**
     * @param null|string $name
     * @return $this
     */
    public function setName(?string $name): Target
    {
        $this->name = $name;

        return $this;
    }

    /**
     * @param AnyOfInterface $anyOff
     * @return self
     */
    public function setAnyOff(AnyOfInterface $anyOff): self
    {
        $this->anyOff = $anyOff;

        return $this;
    }
}
