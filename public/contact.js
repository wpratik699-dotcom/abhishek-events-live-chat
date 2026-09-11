/* =========================================================
   ABHISHEK EVENTS - EDIT YOUR CONTACT DETAILS HERE
   Change the values below, save the file, and refresh your website.
   ========================================================= */

const contactDetails = {
  phone: "+91 95112 61736",
  whatsapp: "+91 95112 61736",
  location: "Pune, Maharashtra",
  businessHours: "Monday – Sunday | 9:00 AM – 9:00 PM",
  email: "your@email.com"
};

document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("[data-phone]").forEach(el => {
    el.textContent = contactDetails.phone;
    if (el.tagName === "A") el.href = "tel:" + contactDetails.phone.replace(/\s/g, "");
  });

  document.querySelectorAll("[data-whatsapp]").forEach(el => {
    if (el.tagName === "A") {
      el.href = "https://wa.me/" + contactDetails.whatsapp;
    }
  });

  document.querySelectorAll("[data-location]").forEach(el => {
    el.textContent = contactDetails.location;
  });

  document.querySelectorAll("[data-hours]").forEach(el => {
    el.textContent = contactDetails.businessHours;
  });

  document.querySelectorAll("[data-email]").forEach(el => {
    el.textContent = contactDetails.email;
    if (el.tagName === "A") el.href = "mailto:" + contactDetails.email;
  });
});
