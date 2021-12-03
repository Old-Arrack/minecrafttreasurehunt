/*!
* Start Bootstrap - Full Width Pics v5.0.4 (https://startbootstrap.com/template/full-width-pics)
* Copyright 2013-2021 Start Bootstrap
* Licensed under MIT (https://github.com/StartBootstrap/startbootstrap-full-width-pics/blob/master/LICENSE)
*/
// This file is intentionally blank
// Use this file to add JavaScript to your project

/*!
    * Start Bootstrap - SB Admin v7.0.4 (https://startbootstrap.com/template/sb-admin)
    * Copyright 2013-2021 Start Bootstrap
    * Licensed under MIT (https://github.com/StartBootstrap/startbootstrap-sb-admin/blob/master/LICENSE)
    */
    //
// Scripts
//

window.addEventListener('DOMContentLoaded', event => {

    // Toggle the side navigation
    const sidebarToggle = document.body.querySelector('#sidebarToggle');
    if (sidebarToggle) {
        // Uncomment Below to persist sidebar toggle between refreshes
        // if (localStorage.getItem('sb|sidebar-toggle') === 'true') {
        //     document.body.classList.toggle('sb-sidenav-toggled');
        // }
        sidebarToggle.addEventListener('click', event => {
            event.preventDefault();
            document.body.classList.toggle('sb-sidenav-toggled');
            localStorage.setItem('sb|sidebar-toggle', document.body.classList.contains('sb-sidenav-toggled'));
        });
    }

});

function show(pass="pass"){
    var invisible = "fas fa-eye-slash eye";
    var visible = "fas fa-eye eye"

    var class_name = document.getElementById("pass-icon").className;

    if (invisible == class_name) {
        document.getElementById("pass-icon").className = visible;
        document.getElementById(pass).type = "text";
    }
    else {
        document.getElementById("pass-icon").className = invisible;
        document.getElementById(pass).type = "password";
    }

}

function show(){
    var eye = "fas fa-eye login-eye";
    var eye_slash = "fas fa-eye-slash login-eye";

    var input_type = document.getElementById("Pass").type;

    if (input_type == "password"){
        document.getElementById("Eye-icon").className = eye;
        document.getElementById("Pass").type = "text";
    }
    else {
        document.getElementById("Eye-icon").className = eye_slash;
        document.getElementById("Pass").type = "password";
    }
}