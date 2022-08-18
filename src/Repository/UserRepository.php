<?php

namespace App\Repository;

use App\Entity\User;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\ORM\NonUniqueResultException;
use Doctrine\Persistence\ManagerRegistry;
use League\OAuth2\Client\Provider\GithubResourceOwner;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Core\User\PasswordUpgraderInterface;

/**
 * @extends ServiceEntityRepository<User>
 *
 * @method User|null find($id, $lockMode = null, $lockVersion = null)
 * @method User|null findOneBy(array $criteria, array $orderBy = null)
 * @method User[]    findAll()
 * @method User[]    findBy(array $criteria, array $orderBy = null, $limit = null, $offset = null)
 */
class UserRepository extends ServiceEntityRepository implements PasswordUpgraderInterface
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, User::class);
    }

    public function add(User $entity, bool $flush = false): void
    {
        $this->getEntityManager()->persist($entity);

        if ($flush) {
            $this->getEntityManager()->flush();
        }
    }

    public function remove(User $entity, bool $flush = false): void
    {
        $this->getEntityManager()->remove($entity);

        if ($flush) {
            $this->getEntityManager()->flush();
        }
    }

    /**
     * Used to upgrade (rehash) the user's password automatically over time.
     */
    public function upgradePassword(PasswordAuthenticatedUserInterface $user, string $newHashedPassword): void
    {
        if (!$user instanceof User) {
            throw new UnsupportedUserException(sprintf('Instances of "%s" are not supported.', \get_class($user)));
        }

        $user->setPassword($newHashedPassword);

        $this->add($user, true);
    }


    /**
     * @throws NonUniqueResultException
     */
    public function findOrCreateFromOauth($socialUser, string $service): ?User
    {
        $em = $this->getEntityManager();
        $_service = ucfirst($service);
        $getMethod = "get{$_service}Id";
        $setMethod = "set{$_service}Id";

        $qb = $this->createQueryBuilder('u')
            ->where("u.{$service}Id = :serviceId")
            ->orWhere('u.email = :email')
            ->setParameter('serviceId', $socialUser->getId());

        if (method_exists($socialUser, 'getNickName')){
            $qb->setParameter('email', $socialUser->getNickname());
        }else{
            $qb->setParameter('email', $socialUser->getEmail());
        }

        /** @var User|null $user */
        $user = $qb
            ->getQuery()
            ->getOneOrNullResult()
        ;

        if ($user){
            if ($user->$getMethod() === null){
                $user->$setMethod($socialUser->getId());

                $em->persist($user);
                $em->flush();
            }

            return $user;
        }

        $user = new User();

        $user
            ->setRoles(['ROLE_USER'])
            ->$setMethod($socialUser->getId());

        if (method_exists($socialUser, 'getNickName')){
            $user->setEmail($socialUser->getNickname());
        }else{
            $user->setEmail($socialUser->getEmail());
        }

        $em->persist($user);
        $em->flush();

        return $user;
    }


    public function findOrCreateFromGithubOauthOld(GithubResourceOwner $owner): User
    {


        /** @var $user User|null */
        $user = $this->createQueryBuilder('u')
                ->where('u.githubId = :githubId')
                ->orWhere('u.email = :email')
                ->setParameters([
                    'email' => $owner->getEmail(),
                    'githubId' => $owner->getId()
                ])
               ->getQuery()
               ->getOneOrNullResult();

        if ($user){
            if ($user->getGithubId() === null){
                $user->setGithubId($owner->getId());
                $this->getEntityManager()->flush();
            }
            return $user;
        }

        $user = (new User())
            ->setRoles(['ROLE_USER'])
            ->setGithubId($owner->getId())
            ->setEmail($owner->getEmail());
        $em = $this->getEntityManager();
        $em->persist($user);
        $em->flush();

        return $user;
    }


}
