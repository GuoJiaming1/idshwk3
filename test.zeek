global gjm :table[addr] of set[string];

event http_header(c: connection, is_orig: bool, name: string, value: string)
{
	if (to_lower(name)=="user-agent")
	{
		if (c$id$orig_h in gjm) 
	  {
		  add gjm[c$id$orig_h][value];
	  }
	  else
	  {
		  gjm[c$id$orig_h]=set(value);
	  }
	}
}

event zeek_done()
{
	for (x in gjm)
	{
		if( |gjm[x]|>=3)
		print fmt("%s is a proxy",x);
	}
}