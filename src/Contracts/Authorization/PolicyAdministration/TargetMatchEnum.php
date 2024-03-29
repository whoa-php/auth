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

namespace Whoa\Auth\Contracts\Authorization\PolicyAdministration;

/**
 * @package Whoa\Auth
 */
abstract class TargetMatchEnum
{
    /** @see http://docs.oasis-open.org/xacml/3.0/xacml-3.0-core-spec-os-en.html #7.11 (table 4) */

    /** Combine result */
    public const MATCH = 0;

    /** Combine result */
    public const NOT_MATCH = self::MATCH + 1;

    /** Combine result */
    public const NO_TARGET = self::NOT_MATCH + 1;

    /** Combine result */
    public const INDETERMINATE = self::NO_TARGET + 1;

    /**
     * @param int $value
     *
     * @return string
     */
    public static function toString(int $value): string
    {
        switch ($value) {
            case static::MATCH:
                $result = 'MATCH';
                break;
            case static::NOT_MATCH:
                $result = 'NOT MATCH';
                break;
            case static::NO_TARGET:
                $result = 'NO TARGET';
                break;
            case static::INDETERMINATE:
                $result = 'INDETERMINATE';
                break;
            default:
                $result = 'UNKNOWN';
                break;
        }

        return $result;
    }
}
