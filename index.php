<?php
session_start();
if (isset($_SESSION['error_message'])) {
    echo "<script>
        document.addEventListener('DOMContentLoaded', function() {
            var errorDiv = document.createElement('div');
            errorDiv.style.color = 'red';
            errorDiv.style.padding = '10px';
            errorDiv.style.margin = '10px 0';
            errorDiv.style.border = '1px solid red';
            errorDiv.style.background = '#ffdddd';
            errorDiv.textContent = '" . $_SESSION['error_message'] . "';
            
            var form = document.querySelector('#estimate-form');
            if (form) {
                form.insertAdjacentElement('beforebegin', errorDiv);
            }
        });
    </script>";
    unset($_SESSION['error_message']); // Clear message after displaying
}
?>


<!doctype html>
<html class="no-js" lang="zxx">

<head>
    <meta charset="utf-8">
    <meta http-equiv="x-ua-compatible" content="ie=edge">
    <title>Tahneem Movers</title>
    <meta name="description" content="Tahneem Movers & Logistics">
    <meta name="keywords" content="Tahneem Movers & Logistics, Moving Services, Office Relocation, Moving, Movers, Relocation">
    <meta name="viewport" content="width=device-width, initial-scale=1">

    <link rel="manifest" href="site.webmanifest">
    <link rel="shortcut icon" type="image/x-icon" href="img/favicon.ico">

    <!-- CSS files -->
    <link rel="stylesheet" href="css/bootstrap.min.css">
    <link rel="stylesheet" href="css/owl.carousel.min.css">
    <link rel="stylesheet" href="css/magnific-popup.css">
    <link rel="stylesheet" href="css/font-awesome.min.css">
    <link rel="stylesheet" href="css/themify-icons.css">
    <link rel="stylesheet" href="css/nice-select.css">
    <link rel="stylesheet" href="css/flaticon.css">
    <link rel="stylesheet" href="css/gijgo.css">
    <link rel="stylesheet" href="css/animate.css">
    <link rel="stylesheet" href="css/slick.css">
    <link rel="stylesheet" href="css/slicknav.css">
    <link rel="stylesheet" href="https://ajax.googleapis.com/ajax/libs/jqueryui/1.11.2/themes/smoothness/jquery-ui.css">

    <link rel="stylesheet" href="css/style.css">
</head>

<body>
    <!-- header-start -->
    <header>
        <div class="header-area ">
            <div class="header-top_area d-none d-lg-block">
                <div class="container">
                    <div class="row align-items-center">
                        <div class="col-xl-4 col-lg-4">
                            <div class="logo">
                                <a href="index">
                                    <img src="img/tahneem-label.png" style="width: 30%; height: auto;">
                                </a>
                            </div>
                        </div>
                        <div class="col-xl-8 col-md-8">
                            <div class="header_right d-flex align-items-center">
                                <div class="short_contact_list">
                                    <ul>
                                        <li><a href="mailto:info@tahneemmovers.com"> <i class="fa fa-envelope"></i> info@tahneemmovers.com</a></li>
                                        <li><a href="#"> <i class="fa fa-phone"></i> +254 796 112 444 || +254 724 897595</a></li>
                                    </ul>
                                </div>

                                <div class="book_btn d-none d-lg-block">
                                    <a class="boxed-btn3-line" href="#">Get Quotation</a>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <div id="sticky-header" class="main-header-area">
                <div class="container">
                    <div class="header_bottom_border">
                        <div class="row align-items-center">
                            <div class="col-12 d-block d-lg-none">
                                <div class="logo">
                                    <a href="index">
                                        <img src="img/tahneem-logo_non-bg.png" alt="TAHNEEM MOVERS & LOGISTICS" style="width: 20%; height: auto;"> TAHNEEM MOVERS & LOGISTICS
                                    </a>
                                </div>
                            </div>
                            <div class="col-xl-9 col-lg-9">
                                <div class="main-menu  d-none d-lg-block">
                                    <nav>
                                        <ul id="navigation">
                                            <li><a  href="index">Home</a></li>
                                            <li><a href="about">About Us</a></li>
                                        
                                            <li><a href="#">Our Services<i class="ti-angle-down"></i></a>
                                                <ul class="submenu">
                                                    <li><a href="our_services#home_moving">Home Moving</a></li>
                                                    <li><a href="our_services#office_relocation">Office Relocation</a></li>
                                                    <li><a href="our_services#warehousing">Warehousing</a></li>
                                                    <li><a href="our_services#packaging">Packaging</a></li>
                                                </ul>
                                            </li>
                                            <li><a href="contact">Contact</a></li>
                                        </ul>
                                    </nav>
                                </div>
                            </div>
                            <div class="col-xl-3 col-lg-3 d-none d-lg-block">
                                <div class="Appointment justify-content-end">
                                    <div class="search_btn">
                                        <a data-toggle="modal" data-target="#exampleModalCenter" href="#">
                                            <i class="ti-search"></i>
                                        </a>
                                    </div>
                                </div>
                            </div>
                            <div class="col-12">
                                <div class="mobile_menu d-block d-lg-none"></div>
                            </div>
                        </div>
                    </div>

                </div>
            </div>
        </div>
    </header>
    <!-- header-end -->

    <!-- slider_area_start -->
    <div class="slider_area">
        <div class="single_slider  d-flex align-items-center slider_bg_1">
            <div class="container">
                <div class="row align-items-center justify-content-center">
                    <div class="col-xl-8">
                        <div class="slider_text text-center justify-content-center">
                            <p>Your move - Our business</p>
                            <h3>Welcome to TAHNEEM MOVERS</h3>
                                <a class="boxed-btn3" href="our_services">Our Services</a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <!-- slider_area_end -->
    <div class="service_area">
        <div class="container">
            <div class="row">
                <div class="col-xl-12">
                    <div class="section_title mb-50 text-center">
                        <h3>
                            Our Services
                        </h3>
                    </div>
                </div>
            </div>
            <!-- service_area  -->
            <div class="service_area">
                <div class="container">
                    <div class="row">
                        <div class="col-md-6 col-lg-4">
                            <div class="single_service">
                                <div class="thumb">
                                    <img src="img/services/home_moving.png" alt="Home Moving Service" loading="lazy">
                                </div>
                                <div class="service_info">
                                    <h3><a href="our_services#home_moving">Home Moving Services</a></h3>
                                    <p>
                                       We
                                        understand that moving homes can be
                                        both exciting and challenging. Our home
                                        moving services are designed to make
                                        your transition as smooth and stress-free
                                        as possible.
                                    </p>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-6 col-lg-4">
                            <div class="single_service">
                                <div class="thumb">
                                    <img src="img/services/office_relocation.png" alt="Office Relocation" loading="lazy">
                                </div>
                                <div class="service_info">
                                    <h3><a href="our_services#office_relocation">Office Relocation Services</a></h3>
                                    <p>
                                       We
                                        specialize in comprehensive office
                                        relocation services designed to minimize
                                        downtime and ensure a seamless
                                        transition to your new workspace.
                                    
                                    </p>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-6 col-lg-4">
                            <div class="single_service">
                                <div class="thumb">
                                    <img src="img/services/warehousing.png" alt="Warehousing Services" loading="lazy">
                                </div>
                                <div class="service_info">
                                    <h3><a href="our_services#warehousing">Warehousing Services</a></h3>
                                    <p>
                                       We
                                        provide secure and efficient
                                        warehousing solutions tailored to meet
                                        the diverse needs of businesses.
                                    </p>
                                </div>
                            </div>
                        </div>

                        <div class="col-md-6 col-lg-4">
                            <div class="single_service">
                                <div class="thumb">
                                    <img src="img/services/packaging.png" alt="Packaging" loading="lazy">
                                </div>
                                <div class="service_info">
                                    <h3><a href="service_detailspackaging">Packaging Services</a></h3>
                                    <p>
                                       We
                                        provide secure and efficient
                                        warehousing solutions tailored to meet
                                        the diverse needs of businesses.
                                    </p>
                                </div>
                            </div>
                        </div>
                        
                    </div>
                </div>
            </div>
            <!--/ service_area  -->
        </div>
    </div>



    <!-- contact_action_area  -->
    <div class="contact_action_area">
        <div class="container">
            <div class="row align-items-center">
                <div class="col-xl-7 col-md-6">
                    <div class="action_heading">
                        <h3>100% secure and safe</h3>
                        <p>Tahneem Movers Kenya, we are commited to quality, safety,
                            and customer satisfaction, we leverage our extensive experience and innovative
                            technology to streamline the moving and logistics process.
                            
                        </p>
                    </div>
                </div>
                <div class="col-xl-5 col-md-6">
                    <div class="call_add_action">
                        <a href="#" class="boxed-btn3">+254 796 112 444 || +254 724 897595</a>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <!-- /contact_action_area  -->
     
    <!-- choose_us_area -->
    <div class="chose_area">
        <div class="container">
            <div class="features_main_wrap">
                <div class="row  align-items-center">
                    <div class="col-xl-5 col-lg-5 col-md-6">
                        <div class="about_image">
                            <img src="img/banner/portfolio-banner.png" style="height: 100%;" alt="" loading="lazy">
                        </div>
                    </div>
                    <div class="col-xl-6 col-lg-6 col-md-6">
                        <div class="features_info">
                            <h3>Why Choose Tahneem Movers?</h3>
                            <ul>
                                <li> 
                                    <div style="color: #d48308">Experienced Professionals: </div>Our team of skilled
                                    movers and logistics experts is dedicated to
                                    providing top-notch service.
                                </li> <br>
                                <li> 
                                    <div style="color: #d48308"> Customized Solutions: </div>We understand that every
                                    move is unique, offering tailored services to meet
                                    specific needs.
                                </li> <br>
                                <li> 
                                    <div style="color: #d48308">State-of-the-Art Technology:</div> Our logistics
                                    management software provides real-time tracking
                                    and inventory control.
                                </li>
                                <li> 
                                    <div style="color: #d48308">Sustainability Commitment:</div> We utilize eco-
                                    friendly materials and practices to minimize our
                                    environmental impact.
                                </li>
                            </ul>

                            <div class="about_btn">
                                <a class="boxed-btn3-line" href="contact">Contact Us</a>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <!--/ choose_us_area -->

    <!-- counter_area  -->
    <div class="counter_area">
        <div class="container">
            <div class="offcan_bg">
                <div class="row">
                    <div class="col-xl-3 col-md-3">
                        <div class="single_counter text-center">
                            <h3> <span class="counter">42</span> <span>+</span> </h3>
                            <p>Countries Covered</p>
                        </div>
                    </div>
                    <div class="col-xl-3 col-md-3">
                        <div class="single_counter text-center">
                            <h3> <span class="counter">97</span> <span>+</span> </h3>
                            <p>Business Success</p>
                        </div>
                    </div>
                    <div class="col-xl-3 col-md-3">
                        <div class="single_counter text-center">
                            <h3> <span class="counter">2342</span></h3>
                            <p>Happy Client</p>
                        </div>
                    </div>
                    <div class="col-xl-3 col-md-3">
                        <div class="single_counter text-center">
                            <h3> <span class="counter">3245</span></h3>
                            <p>Business Done</p>
                        </div>
                    </div>
                </div>
            </div>

        </div>
    </div>
    <!-- /counter_area  -->

    <!-- Our Clients Section -->
    <div class="clients_area" style="background-image: url('img/banner/banner.jpg');">
        <div class="container">
            <div class="row">
                <div class="col-12">
                    <h2 class="client_section_title" style="color: #965d05;">Our Clients</h2>
                    <p class="section_description">
                        At Tahneem Movers & logistics ltd, we pride ourselves on serving a diverse range of clients across various industries. 
                        Our commitment to quality and reliability ensures that each client receives tailored solutions that meet their specific needs. 
                        Below is a snapshot of our clients.
                    </p>
                </div>
                <div class="col-12">
                    <div class="logos_wrapper">
                        <img src="img/client_logos/cog_kajiado.png" alt="County Government of Kajiado" loading="lazy">
                        <img src="img/client_logos/cog_meru.png" alt="County Government of Meru" loading="lazy">
                        <img src="img/client_logos/Dignity_dck_furniture.png" alt="Dignity DCK Furniture" loading="lazy">
                        <img src="img/client_logos/hotpoint.png" alt="Hotpoint Appliances" loading="lazy">
                        <img src="img/client_logos/KCB.png" alt="KCB Bank" loading="lazy">
                        <img src="img/client_logos/LG.png" alt="LG" loading="lazy">
                        <img src="img/client_logos/nairobi_city_council.png" alt="Nairobi City Council" loading="lazy">
                        <img src="img/client_logos/newlight_properties.png" alt="Newlight Properties" loading="lazy">
                        <img src="img/client_logos/safaricom.png" alt="Safaricom" loading="lazy">
                        <img src="img/client_logos/tharaka_nithi_county.png" alt="Tharaka Nithi County" loading="lazy">
                    </div>
                </div>
            </div>
        </div>
    </div>
    <!-- End Our Clients Section -->

    <!-- Estimate_area start  -->
    <div class="Estimate_area overlay">
        <div class="container">
            <div class="row">
                <div class="col-xl-4 col-lg-4 col-md-5">
                    <div class="Estimate_info">
                        <h3>Feel Free To Request A Free Quote</h3>
                        <p>We will coordinate every aspect of your move and keep you posted each step of the way.
                        </p>
                        <a href="#" class="boxed-btn3">+254 796 112 444 || +254 724 897595</a>
                    </div>
                </div>
                <div class="col-xl-8 col-lg-8 col-md-7">
                    <div id="estimate-form" class="form">
                        <form action="/process_form" method="POST" role="form">
                            <div class="Estimate_info">
                                <h2 style="color: white;">Kindly let us know:</h2>
                            </div>
                            <div class="row">
                                <div class="col-xl-6">
                                    <div class="input_field">
                                        <input type="text" name="name" placeholder="Your name" required>
                                    </div>
                                </div>
                                <div class="col-xl-6">
                                    <div class="input_field">
                                        <input type="email" name="email" placeholder="Email" required>
                                    </div>
                                </div>

                                <div class="col-xl-6">
                                    <div class="input_field">
                                        <input type="text" name="size_house_from" placeholder="The size of the house you're moving from" required>
                                    </div>
                                </div>

                                <div class="col-xl-6">
                                    <div class="input_field">
                                        <input type="text" name="from_to_where" placeholder="Where are you moving from, and where to?" required>
                                    </div>
                                </div>

                                <div class="col-xl-6">
                                    <div class="input_field">
                                        <input type="text" name="floor_to_floor" placeholder="From which floor to which floor?" required>
                                    </div>
                                </div>
                                
                                <div class="col-xl-6">
                                    <div class="input_field">
                                        <input type="text" name="moving_schedule" placeholder="When do you want to move?" required>
                                    </div>
                                </div>

                                <div class="col-xl-12">
                                    <div class="input_field">
                                        <textarea name="message" placeholder="Extra Details (Optional:)"></textarea>
                                    </div>
                                </div>
                                <div class="col-xl-12">
                                    <div class="input_field">
                                        <button class="boxed-btn3-line" type="submit">Send Estimate</button>
                                    </div>
                                </div>
                            </div>
                        </form>
                    </div>                    
                </div>
            </div>
        </div>
    </div>
    <!-- Estimate_area end  -->

    <!-- contact_location  -->
    <div class="contact_location">
        <div class="container">
            <div class="row">
                <div class="col-xl-6 col-lg-6 col-md-6">
                    <div class="location_left">
                        <div class="logo">
                            <a href="index">
                                <img src="img/tahneem-logo_non-bg.png" alt="TAHNEEM MOVERS & LOGISTICS" style="width: 20%; height: auto;"> TAHNEEM MOVERS & LOGISTICS
                            </a>
                        </div>
                        <ul>
                            <li><a href="https://www.facebook.com/people/Tahneem-movers/100089774019805/" target="_blank"> <i class="fa fa-facebook"></i> </a></li>
                            <li><a href="https://www.instagram.com/tahneemmovers/" target="_blank"> <i class="fa fa-instagram"></i> </a></li>
                            <li><a href="https://x.com/tahneemmovers" target="_blank"> <i class="fa fa-twitter"></i> </a></li>
                            <li><a href="https://www.tiktok.com/@tahneemmovers" target="_blank"> <i class="fa fa-tiktok"></i> </a></li>
                        </ul>
                    </div>
                </div>
                <div class="col-xl-3 col-md-3">
                    <div class="single_location">
                        <h3> <img src="img/icon/address.svg" alt="Location" loading="lazy"> Location</h3>
                        <p>Westlands, Nairobi Kenya</p>
                    </div>
                </div>
                <div class="col-xl-3 col-md-3">
                    <div class="single_location">
                        <h3> <img src="img/icon/support.svg" alt="Contact Us" loading="lazy"> Contact Us</h3>
                        <p> +254 796 112 444 || +254 724 897595 <br>
                            info@tahneemmovers.com</p>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!--/ contact_location  -->


    <!-- footer start -->
    <footer class="footer">
        <div class="footer_top">
            <div class="container">
                <div class="row">
                    <div class="col-xl-3 col-md-6 col-lg-3">
                        <div class="footer_widget">
                            <h3 class="footer_title">
                                Services
                            </h3>
                            <ul>
                                <li><a href="our_services#home_moving">Home Moving Services</a></li>
                                <li><a href="our_services#office_relocation">Office Relocation</a></li>
                                <li><a href="our_services#warehousing_solutions">Warehousing Solutions</a></li>
                                <li><a href="our_services#packaging_services">Packaging Solutions</a></li>
                            </ul>

                        </div>
                    </div>
                    <div class="col-xl-2 col-md-6 col-lg-2">
                        <div class="footer_widget">
                            <h3 class="footer_title">
                                Company
                            </h3>
                            <ul>
                                <li><a href="about">About</a></li>
                                <li><a href="about#why_us"> Why Us?</a></li>
                            </ul>
                        </div>
                    </div>
                    <div class="col-xl-3 col-md-6 col-lg-3">
                        <div class="footer_widget">
                            <h3 class="footer_title">
                                Industries
                            </h3>
                            <ul>
                                <li><a href="our_services#office_relocation">Office Relocation</a></li>
                                <li><a href="our_services#warehousing_solutions">Ware Housing</a></li>
                            </ul>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <div class="copy-right_text">
            <div class="container">
                <div class="footer_border"></div>
                <div class="row">
                    <div class="col-xl-12">
                        <p class="copy_right text-center">
                            Copyright &copy;<script>document.write(new Date().getFullYear());</script> All rights reserved
                        </p>
                    </div>
                </div>
            </div>
        </div>
    </footer>
    <!--/ footer end  -->

    <!-- Button trigger modal -->
    <!-- Modal -->
    <div class="modal fade custom_search_pop" id="exampleModalCenter" tabindex="-1" role="dialog" aria-labelledby="exampleModalCenterTitle" aria-hidden="true">
        <div class="modal-dialog modal-dialog-centered" role="document">
        <div class="modal-content">
            <div class="serch_form">
                <input type="text" placeholder="search" >
                <button type="submit">search</button>
            </div>
        </div>
        </div>
    </div>

    <!-- JS here -->
    <script src="js/vendor/modernizr-3.5.0.min.js"></script>
    <script src="js/vendor/jquery-1.12.4.min.js"></script>
    <script src="js/popper.min.js"></script>
    <script src="js/bootstrap.min.js"></script>
    <script src="js/owl.carousel.min.js"></script>
    <script src="js/isotope.pkgd.min.js"></script>
    <script src="js/ajax-form.js"></script>
    <script src="js/waypoints.min.js"></script>
    <script src="js/jquery.counterup.min.js"></script>
    <script src="js/imagesloaded.pkgd.min.js"></script>
    <script src="js/scrollIt.js"></script>
    <script src="js/jquery.scrollUp.min.js"></script>
    <script src="js/wow.min.js"></script>
    <script src="js/nice-select.min.js"></script>
    <script src="js/jquery.slicknav.min.js"></script>
    <script src="js/jquery.magnific-popup.min.js"></script>
    <script src="js/plugins.js"></script>
    <script src="js/slick.min.js"></script>


    <!--contact js-->
    <script src="js/contact.js"></script>
    <script src="js/jquery.ajaxchimp.min.js"></script>
    <script src="js/jquery.form.js"></script>
    <script src="js/jquery.validate.min.js"></script>
    <script src="js/mail-script.js"></script>


    <script src="js/main.js"></script>    
</body>

</html>