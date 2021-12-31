<VirtualHost *:80>
    ProxyRequests Off
    ServerName demo.res.ch

    <Proxy balancer://dynamic-cluster>
    <?php
        $members = preg_split("/,/", getenv('DYNAMIC_NODES'));
        foreach ($members as $member) {
            echo "BalancerMember http://$member:3000\n";
        }
    ?>
    </Proxy>

    <Proxy balancer://static-cluster>
    <?php
        $members = preg_split("/,/", getenv('STATIC_NODES'));
        foreach ($members as $member) {
            echo "BalancerMember http://$member:80\n";
        }
    ?>
    </Proxy>

    ProxyPass        /api/addresses/ balancer://dynamic-cluster/
    ProxyPassReverse /api/addresses/ balancer://dynamic-cluster/

    ProxyPass        / balancer://static-cluster/
    ProxyPassReverse / balancer://static-cluster/
</VirtualHost>
