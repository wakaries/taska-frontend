<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

class TaskController extends AbstractController
{
    #[Route('/task', name: 'app_task')]
    public function index(TokenStorageInterface $tokenStorage, HttpClientInterface $httpClient): Response
    {
        $token = $tokenStorage->getToken();
        
        $response = $httpClient->request('GET', 'http://localhost/taska-backend/public/index.php/api/tasks', [
            'auth_bearer' => $token->getBackendToken(),
            'headers' => [
                'Content-Type' => 'application/json'
            ]
        ]);
        $tasks = $response->toArray();

        return $this->render('task/index.html.twig', [
            'tasks' => $tasks,
        ]);
    }
}
