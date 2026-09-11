
rule MAL_WP_Backdoor_CrispWorkerRig_Markers_Sep26 {
   meta:
      description = "Detects the crisp-worker-rig / Prime Scanner Go WordPress backdoor toolkit (SCV 4.5.3) and its injected drop-ins (db.php, object-cache.php, advanced-cache.php) and wp-config.php persistence markers"
      author = "Romain Willmann"
      date = "2026-09-11"
      reference = "Internal Research"
      hash1 = "856ee9bcbef6de5a94c4b39b40d652dd0fd4f49d495db88a1a293cb9addcd00a"
      hash2 = "98bbf22009e31d12e22b966ec85375578ecd046ff67b7427d416df5768042e34"
      hash3 = "b933d5695d2d956ad3eeea9eb38e98fe5e3cf4f482050aa905e247071c56e39e"
      hash4 = "d223a45ff4ecdb06b5ff0e56b95a3eeb725ebac0182f885ba3ccceb577d2228a"
      hash5 = "f0cd664e8f5bd92d7506c3f65b6cbf1bac96a7f74788b8c7f623b230ee788282"
      hash6 = "ed82e64a59ab2139ec777d3adc648573c84311233c73575c8679d695a359c904"
      hash7 = "d20dec59c1761f0ef80c26e74b12d5cf726ba056ebb30a93761dba92c6f613c9"
      hash8 = "047484c4577ca0c56edde3a910369b7c564b970e58dc85cafe8a1bf604e96ec7"
      score = 80
      id = "3f6c2a1e-8b4d-4e7a-9c52-1d0e7b9a4f63"
   strings:
      $x1 = "/* SCV:" ascii
      $x2 = "/* SC_DB_BEGIN:" ascii
      $x3 = "/* SC_OC_BEGIN:" ascii
      $x4 = "/* SC_ADV_BEGIN:" ascii
      $x5 = "/* SCOCV:" ascii
      $x6 = "define( 'WP_CACHE', true ); /* SC_WC */" ascii
      $x7 = "!defined('SC_AUTO_PREPEND')" ascii
      $x8 = "HTTP_X_SC_KEY" ascii
      $x9 = "ameliaclark.com/wp/crisp-worker-rig" ascii
      $x10 = "github.com/miawright/prime-scanner-go" ascii

      $sa1 = "Crisp Worker Rig" ascii
      $sa2 = "Amelia Clark" ascii
      $sb1 = "Prime Scanner Go" ascii
      $sb2 = "Mia Wright" ascii
   condition:
      filesize < 8MB
      and (
         1 of ($x*)
         or all of ($sa*)
         or all of ($sb*)
      )
}

rule MAL_WP_Backdoor_CrispWorkerRig_Decoder_Sep26 {
   meta:
      description = "Detects the two-alphabet character substitution string decoder used by the crisp-worker-rig / Prime Scanner Go WordPress backdoor toolkit"
      author = "Romain Willmann"
      date = "2026-09-11"
      reference = "Internal Research"
      hash1 = "856ee9bcbef6de5a94c4b39b40d652dd0fd4f49d495db88a1a293cb9addcd00a"
      hash2 = "98bbf22009e31d12e22b966ec85375578ecd046ff67b7427d416df5768042e34"
      hash3 = "d223a45ff4ecdb06b5ff0e56b95a3eeb725ebac0182f885ba3ccceb577d2228a"
      hash4 = "f0cd664e8f5bd92d7506c3f65b6cbf1bac96a7f74788b8c7f623b230ee788282"
      hash5 = "047484c4577ca0c56edde3a910369b7c564b970e58dc85cafe8a1bf604e96ec7"
      score = 75
      id = "a8e41d7c-5f23-4b90-b6e1-7c2d94f0a3b5"
   strings:
      $s1 = "for($j=0;$j<strlen($e);$j++){$p=strpos($t,$e[$j]);$r.=($p===false)?$e[$j]:$f[$p];}" ascii
   condition:
      filesize < 8MB
      and $s1
}
