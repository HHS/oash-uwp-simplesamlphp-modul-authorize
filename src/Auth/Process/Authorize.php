<?php

declare(strict_types=1);

namespace SimpleSAML\Module\uwpoash\Auth\Process;

use Exception;
use SimpleSAML\Assert\Assert;
use SimpleSAML\Auth;
use SimpleSAML\Module;
use SimpleSAML\Utils;

use function array_diff;
use function array_key_exists;
use function array_keys;
use function array_push;
use function implode;
use function is_array;
use function is_bool;
use function is_string;
use function preg_match;
use function var_export;

/**
 * OASH: Filter to authorize only users with a proper IAL, AAL (unless they have PIVException).
 * See docs directory.
 *
 * @package SimpleSAMLphp
 */

class Authorize extends Auth\ProcessingFilter
{
    /**
     * Flag to deny/unauthorize the user a attribute filter IS found
     *
     * @var bool
     */
    protected bool $deny = false;

    /**
     * Flag to turn the REGEX pattern matching on or off
     *
     * @var bool
     */
    protected bool $regex = true;

    /**
     * Array of localised rejection messages
     *
     * @var array
     */
    protected array $reject_msg = [];

    /**
     * Flag to toggle generation of errorURL
     *
     * @var bool
     */
    protected bool $errorURL = true;

    /**
     * URL to send a user to if their IAL or AAL is not high enough.
     *
     * @var string
     */
    protected string $loginURL = 'https://preprod.uw.health.gov/saml_login';

    /**
     * Param to send to AMS in case we need to reauthorize.
     *
     * @var string
     */
    protected string $appName = 'AMS-APP-LOA4';

    /**
     * Array of valid users. Each element is a regular expression. You should
     * user \ to escape special chars, like '.' etc.
     *
     * @param array
     */
    protected array $valid_attribute_values = [];

    /**
     * Flag to allow re-authentication when user is not authorized
     * @var bool
     */
    protected bool $allow_reauthentication = false;

    /**
     * The attribute to show in the error page
     * @var string|null
     */
    protected ?string $show_user_attribute = null;

    /**
     * Initialize this filter.
     * Validate configuration parameters.
     *
     * @param array $config  Configuration information about this filter.
     * @param mixed $reserved  For future use.
     */
    public function __construct(array $config, $reserved)
    {
        parent::__construct($config, $reserved);

        // Check for the deny option
        // Must be bool specifically, if not, it might be for an attrib filter below
        if (isset($config['deny']) && is_bool($config['deny'])) {
            $this->deny = $config['deny'];
            unset($config['deny']);
        }

        // #OASH: We do not need this option.
        // Check for the regex option
        // Must be bool specifically, if not, it might be for an attrib filter below
        // if (isset($config['regex']) && is_bool($config['regex'])) {
        //     $this->regex = $config['regex'];
        //     unset($config['regex']);
        // }.
        // Check for the reject_msg option; Must be array of languages.
        if (isset($config['reject_msg']) && is_array($config['reject_msg'])) {
            $this->reject_msg = $config['reject_msg'];
            unset($config['reject_msg']);
        }

        // Check for the appName option.
            if (isset($config['appName']) && is_string($config['appName'])) {
            $this->appName = $config['appName'];
            unset($config['appName']);
        }

        // Check for the loginURL option.
            if (isset($config['loginURL']) && is_string($config['loginURL'])) {
            $this->loginURL = $config['loginURL'];
            unset($config['loginURL']);
        }

        // Check for the errorURL option
        // Must be bool specifically, if not, it might be for an attrib filter below
        if (isset($config['errorURL']) && is_bool($config['errorURL'])) {
            $this->errorURL = $config['errorURL'];
            unset($config['errorURL']);
        }

        if (isset($config['allow_reauthentication']) && is_bool($config['allow_reauthentication'])) {
            $this->allow_reauthentication = $config['allow_reauthentication'];
            unset($config['allow_reauthentication']);
        }

        if (isset($config['show_user_attribute']) && is_string($config['show_user_attribute'])) {
            $this->show_user_attribute = $config['show_user_attribute'];
            unset($config['show_user_attribute']);
        }

        foreach ($config as $attribute => $values) {
            if (is_string($values)) {
                $arrayUtils = new Utils\Arrays();
                $values = $arrayUtils->arrayize($values);
            } elseif (!is_array($values)) {
                throw new Exception(sprintf(
                    'Filter Authorize: Attribute values is neither string nor array: %s',
                    var_export($attribute, true),
                ));
            }

            foreach ($values as $value) {
                if (!is_string($value)) {
                    throw new Exception(sprintf(
                        'Filter Authorize: Each value should be a string for attribute: %s value: %s config: %s',
                        var_export($attribute, true),
                        var_export($value, true),
                        var_export($config, true),
                    ));
                }
            }
            $this->valid_attribute_values[$attribute] = $values;
        }
    }


    /**
     * Apply filter to validate attributes.
     *
     * @param array &$state  The current request
     */
    public function process(array &$state): void
    {
        Assert::keyExists($state, 'Attributes');

        $authorize = $this->deny;
        $attributes = &$state['Attributes'];
        $ctx = [];

        // Store the rejection message array in the $state
        if (!empty($this->reject_msg)) {
            $state['authprocAuthorize_reject_msg'] = $this->reject_msg;
        }
        $state['authprocAuthorize_errorURL'] = $this->errorURL;
        $state['authprocAuthorize_allow_reauthentication'] = $this->allow_reauthentication;
        $arrayUtils = new Utils\Arrays();
        foreach ($this->valid_attribute_values as $name => $patterns) {
            if (array_key_exists($name, $attributes)) {
                // #OASH: change the logic of authorization.
                $values = $arrayUtils->arrayize($attributes[$name]);
                if (is_string($patterns['operator']) && is_numeric($patterns['value']) && $operator = filter_var($patterns['operator'], FILTER_VALIDATE_REGEXP, ["options" => ["regexp" => '/^(<=|>=|==|!=|<|>)$/']])) {


                switch ($patterns['operator']) {
                    case "<":
                    if ($values[0] < $patterns['value']) {
                        $authorize = ($this->deny ? FALSE : TRUE);
                    }
                    break;
                    case "<=":
                    if ($values[0] <= $patterns['value']) {
                        $authorize = ($this->deny ? FALSE : TRUE);
                    }
                    break;
                    case ">":
                    if ($values[0] > $patterns['value']) {
                        $authorize = ($this->deny ? FALSE : TRUE);
                    }
                    break;
                    case ">=":
                    if ($values[0] >= $patterns['value']) {
                        $authorize = ($this->deny ? FALSE : TRUE);
                    }
                    break;
                    case "==":
                    if ($values[0] == $patterns['value']) {
                        $authorize = ($this->deny ? FALSE : TRUE);
                    }
                    break;
                    case "!=":
                    if ($values[0] != $patterns['value']) {
                        $authorize = ($this->deny ? FALSE : TRUE);
                    }
                    break;

                }

                if (!$authorize) {
                    if (isset($patterns['exception']) && is_string($patterns['exception'])) {
                        $exceptions = $arrayUtils->arrayize($attributes[$patterns['exception']]);
                        if (filter_var($exceptions[0], FILTER_VALIDATE_BOOLEAN)) {
                            $authorize = $this->deny;
                        }
                    }
                    // If any checks fail and there is no exception, stop checking.
                    else {
                        break;
                    }

                }
                }

                // foreach ($patterns as $pattern) {
                //     $values = $arrayUtils->arrayize($attributes[$name]);
                //     foreach ($values as $value) {
                //         if ($this->regex) {
                //             $matched = preg_match($pattern, $value);
                //         } else {
                //             $matched = ($value === $pattern);
                //         }.
                // if ($matched) {
                //             $authorize = ($this->deny ? false : true);
                //             array_push($ctx, $name);
                //             break 3;
                //         }
                //     }
                // }.
                // #OASH: end change logic of authorization.
            }
        }

        if (!$authorize) {
            if ($this->show_user_attribute !== null && array_key_exists($this->show_user_attribute, $attributes)) {
                $userAttribute =  $attributes[$this->show_user_attribute][0] ?? null;
                if ($userAttribute !== null) {
                    $state['authprocAuthorize_user_attribute'] = $userAttribute;
                }
            }

            // Try to hint at which attributes may have failed as context for errorURL processing
            if ($this->deny) {
                $state['authprocAuthorize_ctx'] = implode(' ', $ctx);
            } else {
                $state['authprocAuthorize_ctx'] = implode(
                    ' ',
                    array_diff(array_keys($this->valid_attribute_values), $ctx),
                );
            }
            $this->unauthorized($state);
        }
    }


    /**
     * OASH: Users can be redirected if IAL or AAL is too low.
     *
     * Step-Up URL is documented below, but it can be built from config.
     *
     * @param array $state
     */
    protected function unauthorized(array &$state): void
    {
        // Save state and redirect to 403 page.
        $id = Auth\State::saveState($state, 'uwpoash:Authorize');

        // Expected:
        // 'https://dev.uw.health.gov/amsLogin/ssoError?appName=AMS-APP-LOA4&TARGET=https%3A%2F%2Fpreprod.uw.health.gov%2Fsaml_login'
        // 'https://postprod.ams.hhs.gov/amsLogin/ssoError?appName=AMS-APP-LOA4&TARGET=https%3A%2F%2Fpreprod.uw.health.gov%2Fsaml_login'
        // Get AMS domain; trim trailing slash, space or null character.
        // Redirect back to login page once Step-Up is finished.
        $url = rtrim($state['Source']['entityid'], ' /\0') . '/amsLogin/ssoError';

        // $url = Module::getModuleURL('uwpoash/error/forbidden');
        $httpUtils = new Utils\HTTP();
        $httpUtils->redirectTrustedURL($url, ['appName' => $this->appName, 'TARGET' => $this->loginURL]);
        // $httpUtils->redirectTrustedURL($url, ['StateId' => $id]);
    }
}
