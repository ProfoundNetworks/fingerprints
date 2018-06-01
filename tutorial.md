# How to Add a New Fingerprint

This tutorial goes through the steps of adding a new fingerprint to the fingerprint database.
These steps are:

1. Identify the technology you'd like to fingerprint
2. Pick a category for it
3. Find Web sites that use the technology
4. Examine the Web sites and scope out the fingerprint
5. Write code to capture the fingerprint
6. Repeat
7. Test

Next, we'll look at the steps in more detail.

## Identify the Technology

This step requires expert knowledge.
You should research popular Web technologies currently in use and keep up to date with the trends.
Places to start include sites like [builtwith.com](https://trends.builtwith.com/).

For the purposes of this tutorial, we will focus on [hotjar.com](https://www.hotjar.com/).

## Pick a Category

There are six categories:

1. advertising
2. cms
3. ecommerce
4. social_networks
5. web_analytics
6. web_technology_tools

By visiting [hotjar.com](https://www.hotjar.com/), we can see that it best matches the web_analytics category.

## Find Web Sites that Use the Technology

There are several ways to achieve this.
One is to lookup hotjar.com on [builtwith](https://trends.builtwith.com/analytics/Hotjar).
That will give you several examples.

Another is to leverage the links.csv file, a Profound Networks resource.
It is a CSV file in the following format:

    $ gunzip -c links.csv.gz | head -n 2
    source_url|source_domain|destination_url|destination_domain|link_type|anchor_text|datestamp
    http://www.alhilal.com/|alhilal.com|http://js.foxpush.com/alhilalcom.js?sl=1&v=0.6976019132416695|foxpush.com|script_src_external||2018-05-26

Next, we make the following assumption: a Web site links to hotjar.com, it is likely that they actually use Hotjar for their Web analytics.
We can find such Web sites using links.csv:

    $ pv links.csv.gz | gunzip | awk -F '|' '$4 ~ "hotjar.com"' > hotjar.csv

This command can take a while, depending on the size of the links.csv file that you're using.
For example, a 3GB links.csv.gz file took 30 min to process.

For the purposes of this tutorial, we will focus on [alienvault.com](https://www.alienvault.com), a potential customer of Hotjar.

## Scope Out the Fingerprint

This is reasonably straightforward.
Point your browser to www.alienvault.com and examine the page source.
Search for "hotjar" and you'll see conspicuous code like this:

```html
<!-- Hotjar Tracking Code for https://www.alienvault.com/ -->
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

	python2.7 retrieve.py http://www.alienvault.com --timeout 60 > alienvault.com.json

Some points of caution:

- Some sites take a while to load, so you may need a longer timeout.
- Others may load via HTTP but not HTTPS.
- Further still, some sites may only be accessible with the www. prefix, and some without.
- The current retrieve.py script works with Python 2.7 only

Examine the downloaded JSON file using your favorite editor.
Search for hotjar: you'll get several interesting hits.
For example, you'll see that while alientvault.com was loading, it fetched several pages from hotjar.com:

	jq .all_net_reply alienvault.com.json | grep hotjar
	  "https://static.hotjar.com/c/hotjar-484365.js?sv=5": {
	  "https://vars.hotjar.com/rcj-99d43ead6bdf30da8ed5ffcb4f17100c.html": {
	  "https://script.hotjar.com/modules-0db0f4893a41f570b85a1147d48f9d7f.js": {

You'll also find the conspicuous code we identified earlier:

	$ jq .html --raw-output alienvault.com.json | grep h,o,t,j,a,r -A 7
		(function(h,o,t,j,a,r){
			h.hj=h.hj||function(){(h.hj.q=h.hj.q||[]).push(arguments)};
			h._hjSettings={hjid:484365,hjsv:5};
			a=o.getElementsByTagName('head')[0];
			r=o.createElement('script');r.async=1;
			r.src=t+h._hjSettings.hjid+j+h._hjSettings.hjsv;
			a.appendChild(r);
		})(window,document,'//static.hotjar.com/c/hotjar-','.js?sv=');

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

The above simple fingerprint relies on the page (the HTML source for the page) containing a magic string.
We can see that it works for our JSON file:

    $ python extract.py alienvault.com.json
    {"category": "web_technology_tools", "name": "IFrame"}
    {"category": "web_analytics", "name": "hotjar.com"}

Unfortunately, there's a problem: any page containing the above magic string will register as having the fingerprint, even the page you're reading right now!
You can check this:

    $ python retrieve.py https://github.com/ProfoundNetworks/fingerprints/blob/master/tutorial.md | python extract.py -
    {"category": "web_analytics", "name": "hotjar.com"}

This is obviously wrong: our github page merely mentions hotjar.com, it doesn't actually **use** it.
This is known as a **false positive**.
We should avoid false positives as much as possible.
We could _refine_ our fingerprint to look for the magic string only within scripts:

```python
@register_fingerprint('web_analytics', 'hotjar.com')
def WebAnalytics_Hotjar(page, tree, headers, nreq):
    return bool(tree.xpath('//script[contains(text(), "(function(h,o,t,j,a,r){")]'))
```

This way, if the magic string appears outside the script tags, the fingerprint will not be detected.

Let's re-test:

	(fp) sergeyich:fingerprints misha$ python extract.py alienvault.com.json
	{"category": "web_technology_tools", "name": "IFrame"}
	{"category": "web_analytics", "name": "hotjar.com"}

So far so good.  Our fingerprint still works correctly for alienvault.com (**true positive**).

	(fp) sergeyich:fingerprints misha$ python2.7 retrieve.py https://github.com/ProfoundNetworks/fingerprints/blob/master/tutorial.md | python extract.py -
	(fp) sergeyich:fingerprints misha$

Hooray!  The false positive is gone.

Before we end this section, we look at one more way to implement a fingerprint: examining network requests.
Recall that alienvault.com fetched several resources from hotjar.com:

	jq .all_net_reply alienvault.com.json | grep hotjar
	  "https://static.hotjar.com/c/hotjar-484365.js?sv=5": {
	  "https://vars.hotjar.com/rcj-99d43ead6bdf30da8ed5ffcb4f17100c.html": {
	  "https://script.hotjar.com/modules-0db0f4893a41f570b85a1147d48f9d7f.js": {

We could reimplement our fingerprint to rely on that:

```python
@register_fingerprint('web_analytics', 'hotjar.com')
def WebAnalytics_Hotjar(page, tree, headers, nreq):
    return nreq('//script.hotjar.com')
```

The nreq function goes through all the network requests, and searches for the '//script.hotjar.com' substring.
It returns True if the substring is found in any of the request URLs.

## Repeat

The fingerprint is no good if it only works against a single site.
You should go back to your list of Web sites that use the technology and pick another site.
Test your fingerprint against the new site.
If it doesn't show up, then you have a **false negative**, and need to update your fingerprint.
Keep going until you're satisfied that your fingerprint is robust.

## Test

TODO
