$(function() {

    function loadAddress() {

        $.getJSON('/api/addresses/', addresses => {
            const a = addresses[0]
            $('#random-address').html(`${a.street}<br>${a.city.zip} ${a.city.name}<br>${a.country}`);
        })
    }

    setInterval(loadAddress, 2000)
})
