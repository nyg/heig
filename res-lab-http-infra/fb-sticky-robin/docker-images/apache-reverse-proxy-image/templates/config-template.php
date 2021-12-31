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
        ProxySet lbmethod=byrequests
    </Proxy>

    <Proxy balancer://static-cluster>
    <?php
        $members = preg_split("/,/", getenv('STATIC_NODES'));
        foreach ($members as $member) {
            echo "BalancerMember http://$member:80\n";
        }
    ?>
        ProxySet stickysession=ROUTEID
    </Proxy>

    ProxyPass        /api/addresses/ balancer://dynamic-cluster/
    ProxyPassReverse /api/addresses/ balancer://dynamic-cluster/

    <LocationMatch "/">
        ProxyPass        balancer://static-cluster/
        ProxyPassReverse balancer://static-cluster/
        Header add Set-Cookie "ROUTEID=.%{BALANCER_WORKER_ROUTE}e; path=/" env=BALANCER_ROUTE_CHANGED
    </LocationMatch>
</VirtualHost>
