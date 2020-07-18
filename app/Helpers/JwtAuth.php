<?php
namespace App\Helpers;

use Firebase\JWT\JWT;
use Illuminate\Support\Facades\DB;
use App\User;

class JwtAuth {
    
    public $key;
    
    public function __construct() {
        $this->key = 'secret_key-05061995';
    }
    
    public function signup($email, $password, $getToken = null) {
            
        //Buscar si existe el usuario con sus credenciales
        $user = User::where([
            'email' => $email,
            'password' => $password
        ])->first();


        //Comprobar si son correctas(objeto)
        $signUp = false;

        if(is_object($user)) {
            $signUp = true;
        }

        //Generar el token con los datos del usuario identificado
        if($signUp) {

            $token = array (
                'sub' => $user->id,
                'email' => $user->email,
                'name' => $user->name,
                'surname' => $user->surname,
                'description' => $user->description,
                'image' => $user->image,
                'iat' => time(),
                'exp' => time() + (7 * 24 * 60 * 60) //dentro de 1 semana se caduca el token
            );

            $jwt = JWT::encode($token, $this->key, 'HS256');
            $decoded = JWT::decode($jwt, $this->key, ['HS256']);
            // Devolver los datos decodificados o el token en funcion de un parametro
            if(is_null($getToken)) {
                $data = $jwt;
            } else {
                $data = $decoded;
            }
        } else {
            $data = array(
                'status' => 'error',
                'message' => 'Login incorrecto'
            );


        }
        
        return $data;
    }   
    
    public function checkToken($jwt, $getIdentity = false) {
        $auth = false;
        try {
            $jwt = str_replace('"', '', $jwt); //limpia comillas dobles
            $decoded = JWT::decode($jwt, $this->key, ['HS256']);
        } catch (\UnexpectedValueException $e) {
            $auth = false;
        } catch (\DomainException $e) {
            $auth = false;
        }
        
        if(!empty($decoded) && is_object($decoded) && isset($decoded->sub)) {
            $auth = true;
        } else {
            $auth = false;
        }
        
        if($getIdentity) {
            return $decoded;
        }
        
        return $auth;
    }
    
    

}

