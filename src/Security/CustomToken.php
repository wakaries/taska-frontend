<?php
namespace App\Security;

use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;
use Symfony\Component\Security\Core\User\UserInterface;

class CustomToken extends AbstractToken
{
    public function __construct(
        UserInterface $user,
        $backendToken,
        $roles
    ) {
        $this->setUser($user);
        $this->setAttribute('backendToken', $backendToken);
        parent::__construct($roles);
    }

    public function getBackendToken()
    {
        return $this->getAttribute('backendToken');
    }
}