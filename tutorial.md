# How to Add a New Fingerprint

This tutorial goes through the steps of adding a new fingerprint to the fingerprint database.
These steps are:

1. Identify the technology and some of its users
2. Examine the Web sites and identify the fingerprint
3. Write code to capture the fingerprint
4. Repeat for other Web sites

Next, we'll look at the steps in more detail.

## Identify the Technology and Its Users

In a real-life scenario, this step requires expert knowledge and preliminary research.
There are two questions that you need to answer:

1. What is the relevant technology out there worth fingerprinting?
2. Given a specific technology, who are some of its users?

For the purposes of this tutorial, we'll be adding a fingerprint for [HotJar](https://www.hotjar.com/), a popular Web analytics toolkit, with the prior knowledge that [365aviation.com(https://www.365aviation.com/) actively uses HotJar.

## Pick a Category

There are six categories:

1. ``advertising``
2. ``cms``
3. ``ecommerce``
4. ``social_networks``
5. ``web_analytics``
6. ``web_technology_tools``

By visiting [hotjar.com](https://www.hotjar.com/), we can see that it best matches the ``web_analytics`` category.

## Identify the Fingerprint

This is reasonably straightforward.
Point your browser to www.365aviation.com and examine the page source.
Search for "hotjar" and you'll see conspicuous code like this:

```html
<!-- Hotjar Tracking Code for https://www.365aviation.com/ -->
<script>
    (function(h,o,t,j,a,r){
        h.hj=h.hj||function(){(h.hj.q=h.hj.q||[]).push(arguments)};
        h._hjSettings={hjid:484365,hjsv:5};
        a=o.getElementsByTagName('head')[0];
        r=o.createElement('script');r.async=1;
        r.src=t+h._hjSettings.hjid+j+h._hjSettings.hjsv;
        a.appendChild(r);
    })(window,document,'//static.hotjar.com/c/hotjar-','.js?sv=');
</script>
```

In this case, it's pretty easy to scope out this fingerprint because:

1. There is a HTML comment explicitly specifying that Hotjar tracking code follows
2. The script itself is obviously for hotjar (h,o,t,j,a,r)
3. The script also links to some static Hotjar content, likely to be JavaScript

Next, we fetch the homepage using the retrieve.py script:

	$ python chrome.py http://www.365aviation.com --timeout 60 > data/365aviation.com.json

For the purposes of this tutorial, the JSON file is already available in data/365aviation.com.json, just in case you're unable to fetch it for whatever reason.

Some points of caution:

- Some sites take a while to load, so you may need a longer timeout.
- Others may load via HTTP but not HTTPS.
- Further still, some sites may only be accessible with the www. prefix, and some without.

Examine the downloaded JSON file using your favorite editor.
Search for hotjar: you'll get several interesting hits.
For example, you'll see that while 365aviation.com was loading, it fetched several pages from hotjar.com:

```bash
$ jq .all_net_reply data/365aviation.com.json | grep hotjar
  "https://static.hotjar.com/c/hotjar-2674197.js?sv=6": {
  "https://script.hotjar.com/modules.90de377b639fd5b933d2.js": {
  "https://vars.hotjar.com/box-5e66f98b4ee957db209dc6f63e3d59dd.html": {
  "https://in.hotjar.com/api/v2/client/sites/2674197/visit-data?sv=6": {
  "https://ws6.hotjar.com/api/v2/sites/2674197/recordings/content": {
```

You'll also find the conspicuous code we identified earlier:

```bash
$ jq .html data/365aviation.com.json -r | grep 'h,o,t,j,a,r){$' -A 7
    (function(h,o,t,j,a,r){
        h.hj=h.hj||function(){(h.hj.q=h.hj.q||[]).push(arguments)};
        h._hjSettings={hjid:2674197,hjsv:6};
        a=o.getElementsByTagName('head')[0];
        r=o.createElement('script');r.async=1;
        r.src=t+h._hjSettings.hjid+j+h._hjSettings.hjsv;
        a.appendChild(r);
    })(window,document,'https://static.hotjar.com/c/hotjar-','.js?sv=');
```

Armed with the above knowledge, we can move on the the next section.

## Write Code to Capture the Fingerprint 

Recall from the [README.rst](README.rst) that a fingerprint is implemented as a callback.
The callback should return True if the fingerprint is detected.
So, for example, this would be a good start:

```python
@register_fingerprint('web_analytics', 'hotjar.com')
def WebAnalytics_Hotjar(page, tree, headers, nreq):
    return "(function(h,o,t,j,a,r){" in page
```

The above simple fingerprint relies on ``page`` (the HTML source for the page, as a Python ``string``) containing a magic string.
We can see that it works for our JSON file:

```bash
$ python extract.py data/365aviation.com.json
{"category": "web_technology_tools", "name": "IFrame"}
{"category": "web_analytics", "name": "hotjar.com"}
```

Unfortunately, there's a problem: any page containing the above magic string will register as having the fingerprint, even the page you're reading right now!
You can verify this:

    $ python chrome.py https://github.com/ProfoundNetworks/fingerprints/blob/master/tutorial.md | python extract.py -
    {"category": "web_analytics", "name": "hotjar.com"}

This is obviously wrong: our github page merely mentions hotjar.com, it doesn't actually **use** it.
This is known as a **false positive**.
We should avoid false positives as much as possible.
We could _refine_ our fingerprint to look for the magic string only within scripts:

```python
@register_fingerprint('web_analytics', 'hotjar.com')
def WebAnalytics_Hotjar(page, tree, headers, nreq):
	return tree.scripts_contain("function(h,o,t,j,a,r){")
```

This way, if the magic string appears outside the script tags, the fingerprint will not be detected.
The variable ``tree`` is the parsed HTML tree.
It is implemented as a selectolax.lexbor.LexborHTMLParser object: you can read more about it [here](https://selectolax.readthedocs.io/en/latest/lexbor.html#lexborhtmlparser).
You may use any of the methods exposed by that object to implement your fingerprint.

Let's re-test:

	$ python extract.py data/365aviation.com.json
	{"category": "web_technology_tools", "name": "IFrame"}
	{"category": "web_analytics", "name": "hotjar.com"}

So far so good.  Our fingerprint still works correctly for 365aviation.com (**true positive**).

	$ python chrome.py https://github.com/ProfoundNetworks/fingerprints/blob/master/tutorial.md | python extract.py -
	$

Hooray!  The false positive is gone.

Before we end this section, we look at one more way to implement a fingerprint: examining network requests.
Recall that 365aviation.com fetched several resources from hotjar.com:

	jq .all_net_reply data/365aviation.com.json | grep hotjar
	  "https://static.hotjar.com/c/hotjar-484365.js?sv=5": {
	  "https://vars.hotjar.com/rcj-99d43ead6bdf30da8ed5ffcb4f17100c.html": {
	  "https://script.hotjar.com/modules-0db0f4893a41f570b85a1147d48f9d7f.js": {

We could reimplement our fingerprint to rely on that:

```python
@register_fingerprint('web_analytics', 'hotjar.com')
def WebAnalytics_Hotjar(page, tree, headers, nreq):
    return nreq('//script.hotjar.com')
```

The ``nreq`` (short for "network request") function goes through all the network requests, and searches for the '//script.hotjar.com' substring.
It returns True if the substring is found in any of the request URLs.

## Repeat

The fingerprint is no good if it only works against a single site.
You should go back to your list of Web sites that use the technology and pick another site.
Test your fingerprint against the new site.
If it doesn't show up, then you have a **false negative**, and need to update your fingerprint.
Keep going until you're satisfied that your fingerprint is robust.
